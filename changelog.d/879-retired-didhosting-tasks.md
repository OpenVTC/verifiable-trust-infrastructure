### vta-service 0.13.20 / vta-webvh 0.1.2 / vtc-service 0.11.47 — stop sending Trust-Task URIs did-hosting retired in 0.8.3 (#879)

VTC setup against a current VTA failed with `bad gateway: failed to send message:
transport error: request timed out after 30s`, and the error text sent operators
to check an ACL that was never the problem. The VTA was sending
`did-management/did/publish/0.1`, which did-hosting 0.8.3 retired in favour of
`did/register/0.1` (spec `supersededBy`). The host's DIDComm router has no arm
for the retired task and its fallback drops an unrouted type *without replying*,
so every server-managed publish burned the full 30s `send_and_wait` timeout — on
DIDComm, which is the preferred transport whenever a host advertises both. REST
was unaffected: `PUT /api/dids/{mnemonic}` kept its handler and was only
re-identified.

- **vta-service**: the DIDComm `publish_did` now sends `did/register/0.1` with
  the reserved slot's mnemonic as `path` and `force: false`. On the host, an
  owner re-registering their own slot is a publish — content replaced in-batch,
  `version_count` bumped, `created_at` preserved, agent-name registry
  reconciled. `force` stays false deliberately: forcing is how a *different*
  owner takes a slot, so a forced publish would turn a real ownership conflict
  into a silent takeover.
- **vta-service / vta-webvh**: the agent-name `set` / `enable` / `disable` trio
  was folded into one declarative `update` carrying `state: active | parked` by
  the same upstream release, so the VTA's three outbound verbs were hanging 30s
  on DIDComm and 404ing on REST. Both transports now map onto the host's two
  remaining tasks through `AgentNameVerb::{host_endpoint,host_state}`. The VTA's
  own inbound four-verb surface is unchanged — the collapse is a property of the
  host wire, and an operator parking a name still reads `disable`.
- **vtc-service**: the setup wizard's failure hint no longer suggests an ACL
  grant for a transport failure. A hint that names the wrong layer costs more
  than no hint; unrecognised failures keep the ACL wording, which is usually
  right.

Operators who cannot yet upgrade can point the VTA's webvh server record at the
REST transport, or roll the DID-hosting daemon back to 0.8.2.
