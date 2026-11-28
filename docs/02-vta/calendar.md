# The member's calendar

The VTA keeps its principal's calendar across every trust context: the events they registered
for at their communities, read from each community as the membership identifier they hold
there, and the events they hold only a notification of. It fires reminders on their devices,
serves private iCalendar feeds to calendar applications, and keeps each community's signed
reply about a registration as a receipt. The rules are the *Member's calendar* chapter of the
[VTI specification](https://trustoverip.github.io/dtgwg-vti-spec/) (VTI-CAL-001 – 071,
VTI-OPS-111 – 113); the design is [`docs/05-design-notes/vtc-events.md`](../05-design-notes/vtc-events.md)
(phase 3).

| Task | What it does |
|---|---|
| `vta/calendar/list/0.1` | The calendar, earliest first, across the contexts the caller has standing in |
| `vta/calendar/sync/0.1` | Read the communities now, where each context's setting allows |
| `vta/calendar/settings/show/0.1`, `settings/update/0.1` | One context's settings: reading on or off, default reminders, quiet hours |
| `vta/calendar/alerts/set/0.1`, `alerts/clear/0.1` | One event's own reminders |
| `vta/calendar/feeds/create/0.1`, `feeds/list/0.1`, `feeds/revoke/0.1` | Private iCalendar feeds |
| `vta/calendar/export/0.1` | The calendar as iCalendar, and the receipts kept |
| `vta/calendar/receipts/list/0.1`, `receipts/deposit/0.1` | The communities' signed replies, kept as received |
| `vta/calendar/busy/share/0.1` | The choice to share busy times with one booking page |

`pnm calendar list|sync|settings|alerts|feeds|export` drives them; the SDK methods are
`VtaClient::calendar_*`.

## Two tiers, kept per context

A **`mine`** entry is an event the principal registered for. The VTA reads it with
`vtc/events/mine/list/0.2`, signed as the membership identifier its context holds a
`MembershipCredential` for (the smallest, when there are several), over HTTPS only — a
persona-signed document travels only there. It reads only what changed since the last read
(the read mark is kept per community and identifier; a changed identifier starts afresh), and
a reminder already fired stays fired until the event's `sequence` changes (VTI-CAL-013).

A **`notified`** entry is an `event` notification held in the context
([Notifications](notifications.md)): the community, the event, and the period the notification
states — nothing read from the event itself (VTI-CAL-020 – 022). A withdrawn notification is
listed as withdrawn.

Everything is kept per trust context (VTI-CAL-001). A listing answers only for the contexts
the caller has standing in, and naming another context is not an error — it is simply not
answered for, so a client cannot learn that another context holds anything (VTI-CAL-002).
Overlaps are marked among the entries the caller may see (VTI-CAL-023). Deleting a context
deletes its calendar and takes it out of every feed.

**Reading is off until turned on**, per context:
`pnm calendar settings update --context <id> --sync on`. A context whose reading is off is
answered `notSyncing` and its communities are not read.

## Reminders

An entry is reminded at the principal's own alert for it, else the context's default
(`--default-reminders 60,10`). Each offset fires once per event `sequence`; during quiet hours
nothing fires. A reminder reaches the principal's devices as a content-free wake through
their wake channel — the push service and the mediator learn nothing about the event, its
community or the principal (VTI-CAL-043) — and the device reads what is due from the VTA.

## Feeds

`pnm calendar feeds create --context <id> --expires 90d` returns an address once:

```
https://vta.example/calendar/feeds/<64 hex characters>.ics
```

The address is the credential (VTI-CAL-051). The VTA keeps only its SHA-256 digest, never logs
it, and answers an unknown, revoked or expired address with the same bare `404`
(VTI-CAL-052). Each read records when and how often the feed was read (VTI-CAL-054;
`pnm calendar feeds list`). A feed carries titles and times only — `busy` carries times alone
— never access details, registrants, receipts or an identifier of the principal, and its event
UIDs differ from every other feed's (VTI-CAL-053). It covers a context only while its creator
keeps standing there (VTI-CAL-055). It expires within a year; a VTA keeps at most 32 live
feeds.

The route `GET /calendar/feeds/{token}` is a declared REST exception (protocol *iCalendar
subscription*, VTI-OPS-111): a calendar application subscribes by URL and can sign nothing. It
is unauthenticated, on its own per-IP limiter (`calendar-feed`, the `did-log` quota in a bucket
of its own), with the unauthenticated body cap. A feed needs the VTA's `public_url`.

## Receipts

A community answers a registration, a change or withdrawal, a host's decision, and an answer
to an invitation with a signed reply. The client that receives one for a persona DID hands it
to the VTA **exactly as received** (VTI-CAL-031):

```rust
client.calendar_receipts_deposit_json("personal", received_json).await?;
```

The VTA refuses a document that is not such a reply (`notAReply`), one addressed to an
identifier it does not hold in the context (`notAddressed`), and one whose proof is not the
issuer's (`proofInvalid`); it keeps the rest once each (a repeat answers `alreadyKept: true`),
as received, until the principal deletes them (VTI-CAL-030 – 032). `export --receipts` writes
them out.

## Audit

Feed creation and revocation, settings changes, sharing choices, alert changes and reads of
the communities are audited — by reference, never an entry's title, a receipt's content or a
reminder (VTI-CAL-071).

## Not yet

- **Sending busy times** (VTI-CAL-060 – 061): `busy/share` records the choice; sending the
  blocks needs a booking page's `busy/put` task (design phase 7).
- **Reminders on devices without a wake channel** are seen at the device's next read.

## Code

`vta-service/src/operations/calendar.rs` (storage, sync, reminders, feeds, receipts, sweeper),
`vta-service/src/trust_tasks/calendar.rs` (+ `calendar_tests.rs`),
`vta-service/src/routes/calendar_feed.rs`, `vta-sdk/src/client/calendar.rs`,
`vta-cli-common/src/commands/calendar.rs`.
