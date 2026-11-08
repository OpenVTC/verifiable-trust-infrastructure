# Collection for the principal's identifiers

A notification addressed to a persona DID is delivered, as far as its sender can tell, when the
mediator the persona's DID document names has queued it. It reaches anybody only when some party
**collects** it — holds that DID's connection to the mediator and takes what is queued. The
mediator permits **one connection per DID**: a second evicts the first.

The VTA holds the keys of the DIDs it mints for its principal, so it can be that party. A client
of the principal can be too — a desktop wallet that holds the persona's keys — and then the two
must agree which of them it is. This page describes how (VTI-NTF-080 – 098, trust-tasks-tf
`vta/collection/{claim,release,list}/0.1` and `vta/collection/settings/{show,set}/0.1`).

## Who collects

For every identifier the VTA collects for **unless a client has claimed it** (VTI-NTF-080) — a
`did:webvh` it holds in one of the principal's contexts whose current document advertises a
`TSPTransport` or `DIDCommMessaging` service naming a mediator DID — exactly one of:

| Collector | When |
|---|---|
| `client` | A client holds a **collection claim** for it that is in force. |
| `vta` | Collection by default is enabled for its context, and nothing below applies. |
| `none` / `disabled` | Collection by default is disabled for its context, or the operator has suspended it. |
| `none` / `conflict` | Another connection kept closing the VTA's; it stopped (below). |
| `none` / `limit` | The VTA is at its bound on identifiers collected for. |

The VTA never collects for, and never grants a claim on:

- its own DID (it collects for that as a node);
- any DID that is itself the subject of an ACL entry here (a node or client that collects for
  itself);
- an identity `provision/integration` minted for another party (recorded when the bundle is
  made — VTI-NTF-080 item 2);
- the mediator it is configured with, and any DID in `[collection] exclude`.

### Integrations provisioned before this release

Since collection by default is **on** for every context (below), the VTA must know which of its
DIDs are integrations' before it connects for anything. `provision/integration` has recorded that
since collection claims were introduced; for an integration provisioned before then, the VTA works
it out from its own records **once, at the first boot of this release**, before the collector opens
a connection:

- a `key.secret_export` audit row on the `provision-integration` channel — one of the DID's keys
  was exported into a provisioning bundle; or
- a key record of the DID labelled the way provisioning labels them — the holder's `did:key`
  followed by ` signing key` or ` key-agreement key`.

Each identifier recorded is logged, and the run is audited once
(`collection.provisioned_backfilled`, listing them). A row `backfill:provisioned` marks it done, so
it never runs again.

What neither shows stays a candidate: an audit row pruned by retention, an audit trail kept only in
an external sink, a key relabelled since. **Before upgrading**, list each context (`pnm collection
list --context <id>`) and add the DID of any integration that collects for itself to
`[collection] exclude`; after upgrading, check the same list — an integration shown with collector
`vta` is one to exclude (disable the context, below, while you do).

## Collection by default: a setting of each context

Collection by default is **enabled for every context unless it is disabled there** (VTI-NTF-094).
The setting belongs to the context, not to the VTA: it applies to that context's identifiers alone —
not to its ancestors' or descendants' — is stored (so it survives a restart, a TEE's included), and
is changed at run time, taking effect when the VTA answers. A context that has never been changed
is enabled.

```sh
pnm collection status  --context personal   # the setting, who/when, suspension, counts by collector
pnm collection disable --context personal   # stop collecting for its unclaimed personas
pnm collection enable  --context personal   # start again
```

- **Reading** (`vta/collection/settings/show/0.1`) needs standing in the context. It answers the
  setting, the DID that last changed it and when (absent while it never has been), and whether the
  operator's suspension is in force.
- **Changing** (`vta/collection/settings/set/0.1`, VTI-NTF-095) needs **administrative authority
  over the context** (VTI-ACL-022): an admin entry whose contexts include it or an ancestor of it,
  or a super-admin. Standing alone — enough to claim, list or read the setting — is not: the
  setting decides for every client and every persona in the context at once.
  - **Disabling** stops collection and closes every connection the VTA holds for the context's
    personas **before it answers**.
  - **Enabling** starts collecting for them, including any the VTA had stopped for a conflict
    (below); it answers without waiting for the connections to open.
  - Setting the value already held answers `changed: false` and changes nothing — not even who
    last changed it.
  - Every change is audited (`collection.setting.enabled` / `collection.setting.disabled`) with the
    caller and the context, **before** it is applied; a change that cannot be audited is refused.

**When to disable it.** A client released before collection claims connects for the principal's
personas without claiming them. A VTA collecting beside it is the second connection to every such
persona, and each evicts the other (VTI-NTF-085) — losing exactly the notifications collection
exists to deliver. Disable the context while such a client is in use there, and enable it again
once every client claims first (VTI-NTF-097). The failure is visible either way: the VTA lists the
persona as `none` / `conflict` and audits it. While disabled, claims are still granted, renewed,
released and listed, so clients can adopt them first.

## The operator's suspension

The operator keeps one switch, and it can only **stop** collection (VTI-NTF-098):

```toml
[collection]
suspend = false              # VTI-NTF-098: true suspends collection by default in every context
max_identifiers = 64          # VTI-NTF-088: the bound on identifiers collected for
max_claim_secs = 2592000      # the longest claim granted (thirty days at most)
default_claim_secs = 86400    # granted when a client asks for no duration
clock_skew_secs = 60          # waited after a claim ends before the VTA resumes
exclude = []                  # DIDs never collected for
```

While `suspend = true`, every context is treated as disabled, whatever its setting, and **no
context's setting changes**; `status` and `settings/show` say `suspendedByOperator: true`. A context
administrator can still change a setting — it is stored and answered, and applies once the
suspension is lifted. Removing it (or setting `false`) lifts it: each context's own setting applies
again, and the conflicts in every enabled context are cleared, as enabling does. There is no
operator key that enables collection for a context whose setting disables it.

The suspension is read at boot. Engaging or lifting it is audited at the boot that applies it
(`collection.suspended` / `collection.suspension_lifted`, actor `operator:config`). In a fleet
enclave the tenant overlay may deliver `{"collection":{"suspend":true}}`; the overlay can only
suspend — a `false` there leaves the baked value — so lifting it is no longer delivering it. It is
not a `config/patch` key: a patch is lost when an enclave restarts.

### Upgrading from `collect_by_default`

The earlier operator setting `[collection] collect_by_default` (VTI-NTF-093, now withdrawn) is
**ignored, whatever its value**, with a warning at boot naming the replacement. The VTA keeps
booting: a configuration carrying the key is not refused, because the old default (`false`) was
written into deployed configurations by these docs and refusing it would stop a working VTA for a
value that no longer means anything. What it means for a deployment:

| Was | Now |
|---|---|
| absent, or `collect_by_default = false` (the old default) | Every context collects by default. Exclude integrations first (above); disable any context whose clients collect without claiming, or set `suspend = true` until you have. |
| `collect_by_default = true` | No change in behaviour. |

The tenant overlay's `collection.collect_by_default` is accepted and ignored the same way. Remove
the key once you have read the warning.

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
  collection is enabled for a context, are opened in the same few seconds.
- **Inside the boundary** (VTI-NTF-089). The keys are loaded in the VTA's own process (audited as
  `key.internal_use`, purpose `collection`) — inside the enclave for a TEE VTA — and never leave
  it. A key held as an internal (non-extractable) key cannot be collected with.
- **Conflicts** (VTI-NTF-085). The transport backs off on a connection that is closed soon after
  it opened. After **5** such closures within **15 minutes** the VTA stops, records the conflict
  in the audit trail (`collection.conflict`), and lists the identifier as `none` / `conflict`
  until a client claims it — the way the principal settles it — or collection by default is enabled
  for its context after being disabled (VTI-NTF-095), or the operator's suspension is lifted. Once
  a claim ends, the VTA tries again.
- **Rotation and mediator change** (VTI-NTF-090). A rotation rebuilds the session with the new
  keys and leaves any claim in place. When the document names a different mediator the VTA
  collects at the new one; it does **not** yet keep collecting at the previous one for a period
  (a SHOULD of VTI-NTF-090).
- **Deletion** (VTI-NTF-090). Deleting a context ends its claims and drops its setting, so a
  context created again under the same id starts enabled; a deleted or deactivated DID
  stops being collected for on the collector's next pass, and its claims are swept.

## Code

`vta-service/src/operations/collection.rs` (candidates, claims, the plan, each context's setting,
the suspension, the upgrade backfill, the shared control),
`vta-service/src/messaging/collector.rs` (the sessions),
`vta-service/src/trust_tasks/collection.rs` (the tasks, and the answer as a persona),
`vta_sdk::client` (`collection_{claim,release,list,settings_show,settings_set}` and their `_json`
forms),
`vta-cli-common/src/commands/collection.rs` (`pnm collection …`).
