# vti-vtn

The **Verifiable Trust Network** (VTN) protocol: the part of a network that is not a service. A VTN curates a nestable set of communities and networks (`dtgwg-vti-spec` *The Verifiable Trust Network*, VTI-VTN-001 – 063). Every relationship in it is a DTG credential.

Used by:
- **`vtc-service`**: a community as a network member. It acknowledges or repudiates listings, registers groups, relays broadcasts, and hands out room-pass evidence.
- **The VTN service and its `nnm` CLI**, in [OpenVTC/verifiable-trust-network](https://github.com/OpenVTC/verifiable-trust-network). They depend on this crate, never the reverse.

| Module | What |
|---|---|
| `model`, `lifecycle` | Entries (community or network), entry state, and the state machine. Membership is reachable only through the listed party's acknowledgement (VTI-VTN-013). |
| `credentials` | The listing VSC and the unsigned membership offer, plus the member side: acknowledge and repudiate |
| `verify` | Credential and signed-document verification behind a purpose-checked `KeyResolver`. Accepts a single proof or a proof set. |
| `identity`, `did_key` | Signing as a party through any `affinidi_data_integrity` signer |
| `status` | W3C Bitstring Status Lists |
| `index`, `graph`, `directory` | Signed network index, DTG graph export, directory search and federation types |
| `groups` | Network roles, and group registration: the member's signed `vtn/groups/register` request, accepted by a `groupRegistered` VSC |
| `relay` | Signed broadcast envelopes, hop chains, and receipts |
| `rooms` | Network room passes issued on chained group evidence |
| `client`, `tasks`, `status_client` (feature `client`) | HTTPS client: `vtn/*` Trust Tasks signed by the caller (`VtnClient::task`), and a status-list checker |

Listings and repudiations use the DTG VSC registry's [`lists/1`](https://github.com/trustoverip/dtgwg-vsc-registry/tree/main/predicates/lists/1) and [`repudiates/1`](https://github.com/trustoverip/dtgwg-vsc-registry/tree/main/predicates/repudiates/1); a listing's `object.value` is `{ nodeType: "VTC" | "VTN", framework }`. The group predicate (`groupRegistered/1`) stays in the `https://openvtc.org/vtn/vsc/` namespace until the DTG working group registers them. See [dtgwg-cred-spec discussion #82](https://github.com/trustoverip/dtgwg-cred-spec/discussions/82).
