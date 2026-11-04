# Notifications

A **notification** is a signed statement by an *originator*, addressed to one DID, that a
thing exists which the addressee — or the parties it stands for — may take part in: where the
thing is held, its identifier there, the Trust Task that opens it, and the *audience* it
concerns. It carries nothing of the thing itself, confers no authority, and is no evidence that
anyone may take part. The rules are the *Notifications* chapter of the
[VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/) (VTI-NTF-001 – 063); the
kinds are its Appendix G. The tasks:

| Task | Who sends it | To |
|---|---|---|
| `notifications/notify/0.1` | the originator | the addressee (an individual, group, community or network) |
| `notifications/relay/0.1` | a party that stands for others | one party it stands for |
| `vta/notifications/list/0.1` | the principal's client | its VTA |
| `vta/notifications/show/0.1` | the principal's client | its VTA |
| `vta/notifications/dismiss/0.1` | the principal's client | its VTA |
| `vta/notifications/deposit/0.1` | the principal's client, for a persona DID whose socket it holds | its VTA |
| `vtc/notifications/{list,show,relay}/0.1` | a community administrator | the community ([`docs/03-vtc/notifications.md`](../03-vtc/notifications.md)) |

## Relays

A relay carries the document its relayer received **exactly as received**, proof included, so
the final recipient verifies the originator's own signature and every relayer's. Each forwarded
document must be addressed to the relayer that forwarded it, and a delivery carries at most four
relays. `vta_sdk::notifications::verify_delivery` checks all of it and is the only way to a
`VerifiedDelivery`; a client verifying what `vta/notifications/show` returned uses it too.

## The VTA as recipient

`notifications/notify` and `relay` reach the VTA over TSP or DIDComm from parties that usually
hold no ACL entry here, so they dispatch on a zero-authority claim and the **acceptance policy**
decides what is kept (VTI-NTF-030). The policy this VTA states holds a notification only when
the party that delivered it — the originator, or for a relay the *last relayer*, never the
originator (VTI-NTF-031) — is:

- a party holding an ACL entry at the VTA;
- the issuer of a membership credential held in the context (a community, group or network the
  principal belongs to), or a party to a relationship credential held there;
- a DID in `[notifications] accept_from`;

or `[notifications] accept_any = true`. Everything else is declined. A verified document is
answered with the same receipt (`notificationId`, `revision`) whether it was held, declined or
discarded, so a sender learns nothing of the principal's relationships (VTI-NTF-023).

What is held:

- one record per addressee, originator and `notificationId`; a higher revision replaces it (a
  withdrawal included), an equal or lower one changes nothing (VTI-NTF-022);
- in the trust context of the DID it was addressed to (VTI-NTF-050), in the `notifications`
  keyspace, which is backed up — a held notification cannot be fetched again;
- bounded: 256 from any one originator, 1024 delivered by any one party (VTI-NTF-033);
- discarded `[notifications] retain_lapsed_days` (default 30) after it was withdrawn or its
  `validUntil` passed (VTI-NTF-052); one received after its `validUntil` is never held.

```toml
[notifications]
accept_from = ["did:webvh:…:partner.example"]
accept_any = false
retain_lapsed_days = 30
```

Holding, listing, reading and dismissing a notification send nothing to anyone (VTI-NTF-053).
Opening the thing — `subject.openWith` sent to `subject.heldBy` — is the client's step, at the
principal's choice.

**Addressing.** The VTA receives directly only what is addressed to its own DID (the transports
deliver to it, and the dispatch spine checks `recipient`). A notification addressed to a persona
DID whose mediator socket a client holds reaches that client, which hands it over.

## Deposit: what a client received for a persona DID

A client that receives a `notifications/notify` or `notifications/relay` for a DID whose keys
the principal's VTA holds **must** deposit it with `vta/notifications/deposit/0.1`, exactly as
received (VTI-NTF-054): the received JSON itself, never a value re-serialised from a typed form
or re-signed. It applies no acceptance policy of its own — not depositing is declining, and that
is the VTA's decision — and answers the sender itself with the receipt `notifications/notify`
defines, the same whatever the VTA answers.

The VTA treats a deposit exactly as a direct delivery (VTI-NTF-055, VTI-NTF-056):

1. the client needs standing in `contextId` (`permissionDenied` otherwise), before the document
   is read;
2. the document's `recipient` must be a DID the VTA holds keys of **in that context**, else
   `vta/notifications/deposit:notAddressedHere`;
3. every layer is verified as for a direct delivery, and the VTA's own receipt checks — the
   acceptance window, `expiresAt`, and the record of accepted document identifiers — are applied
   to the deposited document **at the time of the deposit**; any failure is
   `vta/notifications/deposit:documentInvalid`, and nothing is held;
4. the acceptance policy counts the party that **delivered** the document (its originator, or
   the last relayer) — never the depositing client or its ACL entry;
5. the same one record per originator and `notificationId`, and the same receipt
   (`notificationId`, `revision`) whatever was done. A repeat changes nothing (retry class 2).

```sh
pnm notifications deposit received.json --context personal    # `-` reads stdin
```

SDK: `VtaClient::notifications_deposit_json` (and the typed `notifications_deposit`).

## The principal's view

```sh
pnm notifications list --context personal --kind election
pnm notifications show hn-… --context personal      # the record and the document as received
pnm notifications dismiss hn-… --context personal
```

A client needs standing in the context (`list`/`show`/`dismiss` on an ACL entry whose act scope
covers it); a record in another context is `notificationUnknown` (VTI-NTF-051). Dismissed and
lapsed records are listed only when asked for (`--include-dismissed`, `--include-lapsed`).
SDK: `VtaClient::notifications_{list,show,dismiss}` and their `_json` forms.

## The election kind

A community that holds an election under a credential roll naming a **member party** — a party
that is itself a member of the community — notifies that party once the ballot box has
registered the election, and withdraws the notification (a higher revision, `status:
withdrawn`) if the election is cancelled or closed before voting closes (VTI-NTF-060/061): the
community's own list never shows such an election to the party's members, and the community
holds no record of them. The notification names the community (`heldBy`), the `electionId`,
`vtc/elections/show/0.6`, the party (`audience`) and the voting period, and nothing else.

At the VTC the notice is recorded before it is sent and the election sweeper is its only
sender, through the durable member push (`docs/03-vtc/elections.md`).

A VTC that receives a notification holds it by its own stated policy and relays it to its
members only when an administrator decides to, after being shown what a relay discloses — for an
election, that the community is a member of the one holding it (VTI-NTF-046). The
administrators' view and the relay decision are described in
[`docs/03-vtc/notifications.md`](../03-vtc/notifications.md).

## Collected by the VTA

When collection by default is on, the VTA itself holds the mediator connection of every persona
DID no client has claimed, and takes what it collects there exactly as a deposit
(VTI-NTF-086). See [Collection](collection.md).
