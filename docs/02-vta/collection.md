# Collection for the principal's identifiers

A notification addressed to a persona DID is delivered, as far as its sender can tell, when the
mediator the persona's DID document names has queued it. It reaches anybody only when some party
**collects** it — holds that DID's connection to the mediator and takes what is queued. The
mediator permits **one connection per DID**: a second evicts the first.

The VTA holds the keys of the DIDs it mints for its principal, so it can be that party. A client
of the principal can be too — a desktop wallet that holds the persona's keys — and then the two
must agree which of them it is. This page describes how (VTI-NTF-080 – 093, trust-tasks-tf
`vta/collection/{claim,release,list}/0.1`).

## Who collects

For every identifier the VTA collects for **unless a client has claimed it** (VTI-NTF-080) — a
`did:webvh` it holds in one of the principal's contexts whose current document advertises a
`TSPTransport` or `DIDCommMessaging` service naming a mediator DID — exactly one of:

| Collector | When |
|---|---|
| `client` | A client holds a **collection claim** for it that is in force. |
| `vta` | Collection by default is on, and nothing below applies. |
| `none` / `disabled` | Collection by default is off (the default). |
| `none` / `conflict` | Another connection kept closing the VTA's; it stopped (below). |
| `none` / `limit` | The VTA is at its bound on identifiers collected for. |

The VTA never collects for, and never grants a claim on:

- its own DID (it collects for that as a node);
- any DID that is itself the subject of an ACL entry here (a node or client that collects for
  itself);
- an identity `provision/integration` minted for another party (recorded when the bundle is
  made — VTI-NTF-080 item 2);
- the mediator it is configured with, and any DID in `[collection] exclude`.

An integration provisioned **before** this release has no record that it was provisioned. List
its context with `pnm collection list` before turning collection on, and add any such DID to
`[collection] exclude`.

## Collection by default is off

```toml
[collection]
collect_by_default = false   # VTI-NTF-093: off unless the operator enables it
max_identifiers = 64          # VTI-NTF-088: the bound on identifiers collected for
max_claim_secs = 2592000      # the longest claim granted (thirty days at most)
default_claim_secs = 86400    # granted when a client asks for no duration
clock_skew_secs = 60          # waited after a claim ends before the VTA resumes
exclude = []                  # DIDs never collected for
```

A client that predates collection claims connects for the principal's personas **without
claiming them**. A VTA collecting beside it would be the second connection to every persona,
and each would evict the other — losing exactly the notifications collection exists to deliver.
So the VTA collects for nothing until the operator turns it on, which should happen only once
every client in use claims first. Claims are granted, renewed, released and listed either way,
so clients can adopt them before the switch.

The setting is read at boot (and from the tenant overlay in a fleet enclave:
`{"collection":{"collect_by_default":true}}`). A change is recorded in the audit trail
(`collection.enabled` / `collection.disabled`) at the boot that applies it. Turning it off
closes every connection the VTA held for a persona. It is not a `config/patch` key: a patch is
lost when an enclave restarts.

## Claims

A claim is a **lease**: the claimant is the identifier's one collector until a stated end.

```sh
pnm collection claim   --context personal --identifier did:webvh:…  [--duration 86400]
pnm collection release --context personal --identifier did:webvh:…
pnm collection list    --context personal [--collector none]
```

- **Claim** (VTI-NTF-082): needs standing in the context. Before it answers, the VTA stops
  collecting for the identifier and closes its connection. The end is no later than the stated
  maximum (`max_claim_secs`, thirty days at most). A claim by the client already holding it is a
  renewal and answers `renewed: true`. `claimHeld` while another client's claim is in force;
  `notCollectable` for anything the table above excludes.
- **The client** (VTI-NTF-083): claims before it connects, asks for twenty-four hours, renews
  at half-time, and closes its connection before the end (less its own skew) unless it renewed.
- **Release** (VTI-NTF-084): by the claimant — which has already closed its connection — ends the
  claim at once, and the VTA collects again at once. By anyone else with standing — a principal
  cleaning up after a lost device — the claim becomes **unrenewable** and still ends at its end
  (`claimNotRenewable` on the next renewal); the VTA resumes only after the end plus its skew. A
  claim whose claimant loses standing (entry removed, expired, or narrowed) is unrenewable too. A
  rollover of the claimant's entry or a key swap (`acl/swap-key`) carries the claim.
- **List** (VTI-NTF-091): every identifier above, with its collector, the claim's claimant, end
  and renewability, or why nobody collects for it. Nothing about another context.

## What the VTA does with what it collects

- A `notifications/notify` or `notifications/relay` is taken **exactly as a deposit**
  (VTI-NTF-086, [notifications](notifications.md)): the document must be bound to the party that
  delivered it, every layer is verified, the acceptance window and replay guard apply at the time
  of collection, the acceptance policy counts the delivering party, and one record is held. The
  VTA answers the sender **as the persona** — issuer and proof are the persona's — with the same
  receipt whatever it did.
- **Every other operation is refused** as one the identifier does not serve
  (`unsupportedType`, VTI-NTF-087, VTI-OPS-081), as the persona, whatever authority its sender
  holds at the VTA. Nothing is performed, held or relayed, and no answer names the VTA's own DID.
- A TSP relationship request is answered as TSP requires of a recipient, and a DIDComm trust ping
  is answered; anything else carrying no operation is dropped.
- Senders without standing here share the VTA's one bound for such senders (VTI-TRN-029,
  VTI-NTF-088); a sender with an ACL entry is charged to its own budget. Neither bound is per
  identifier.

## Connections

- **One per identifier.** Each collected identifier has its own session: its own TDK and ATM
  holding only that identifier's keys, one websocket at its mediator, DIDComm and TSP on it. The
  VTA never opens a second session for a DID it already collects for, and never one for its own.
- **One context per connection** (VTI-NTF-089). Connections for identifiers of different contexts
  are separate websockets authenticated as separate DIDs. What they reveal **in common** to the
  mediator (VTI-TRN-027) is that they come from the same network address and, at boot or when
  collection is turned on, are opened in the same few seconds.
- **Inside the boundary** (VTI-NTF-089). The keys are loaded in the VTA's own process (audited as
  `key.internal_use`, purpose `collection`) — inside the enclave for a TEE VTA — and never leave
  it. A key held as an internal (non-extractable) key cannot be collected with.
- **Conflicts** (VTI-NTF-085). The transport backs off on a connection that is closed soon after
  it opened. After **5** such closures within **15 minutes** the VTA stops, records the conflict
  in the audit trail (`collection.conflict`), and lists the identifier as `none` / `conflict`
  until a client claims it — the way the principal settles it. Once that claim ends, the VTA tries
  again.
- **Rotation and mediator change** (VTI-NTF-090). A rotation rebuilds the session with the new
  keys and leaves any claim in place. When the document names a different mediator the VTA
  collects at the new one; it does **not** yet keep collecting at the previous one for a period
  (a SHOULD of VTI-NTF-090).
- **Deletion** (VTI-NTF-090). Deleting a context ends its claims; a deleted or deactivated DID
  stops being collected for on the collector's next pass, and its claims are swept.

## Code

`vta-service/src/operations/collection.rs` (candidates, claims, the plan, the shared control),
`vta-service/src/messaging/collector.rs` (the sessions),
`vta-service/src/trust_tasks/collection.rs` (the tasks, and the answer as a persona),
`vta_sdk::client` (`collection_{claim,release,list}` and their `_json` forms),
`vta-cli-common/src/commands/collection.rs` (`pnm collection …`).
