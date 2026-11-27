# Community events

A community runs **events** — a meetup, a workshop, a social, an AGM — in **calendars**:
the community's own, and one per group that wants one. Members see the events their
audience admits, register, change or withdraw their registration, and the community answers
each change with a signed reply the member's own agent keeps as a receipt. Events carry no
authority: nothing about an event, a registration or an attendance is read by an
authorization decision.

Specification: the VTI Community Events chapter (VTI-EVT-001 – 095). Wire: the
`vtc/events/*` 0.1 Trust Tasks. Design: [`vtc-events.md`](../05-design-notes/vtc-events.md),
which also describes the later phases (invitations and the `event` notification, the
member's calendar across communities in their VTA, check-in and tickets, meetings, booking
pages).

## Who runs what

| | Authority |
|---|---|
| The community's calendars and every event | `vtc.events.manage` (unqualified) |
| A group's calendar and its events | `vtc.events.manage` at `group:<groupId>`, or managing that group (`vtc.groups.manage` at `group:<groupId>`) |
| One event | its **hosts**: whoever runs its calendar, and members appointed with `vtc/events/hosts/appoint` (`vtc.events.manage` at `event:<eventId>`) |

The member who creates an event is its first host. Hosts are peers: any host may appoint
another active member or remove a host, but a published event always keeps one. A host's
appointment is reviewed on the action list when the member who appointed them leaves or
loses the authority they appointed with, as group managers' and board facilitators' are.

## An event's life

`draft` → `published` → (`cancelled`). A draft is seen only by its hosts and takes no
registrations; publishing makes it visible to its audience; a published event is cancelled,
never deleted, and a draft is deleted, never cancelled. Whether an event has ended is read
from its time.

**Time** is local time in an IANA zone plus a duration, as JSCalendar states it
(`"start": "2026-11-30T18:30:00", "timeZone": "Europe/London", "duration": "PT1H30M"`). A
change in a zone's daylight-saving rules moves nothing a host chose. A change of time,
place, status or kind after publication raises the event's `sequence`, which registrants'
agents compare against their own copy.

**Audience** is `members`, a list of groups (a badge is a group, so badges work here), or a
list of roles, optionally narrowed by a rule in the dynamic-group language (tenure,
credential-sourced fields, personhood). It is checked live on every read and registration.
An unlisted event is shown only to someone who names it.

## Registration

| Setting | Effect |
|---|---|
| `mode: open` | a registrant is going at once, or waitlisted when full |
| `mode: approval` | each registration waits for a host (`vtc/events/registrations/decide`); `maybe` is not offered |
| `mode: closed` | for information only |
| `capacity`, `waitlist` | places count plus-ones; with a waitlist, the first waitlisted that fits becomes going when a place frees |
| `plusOnes` | guests each registrant may bring |
| `opensAt`, `closesAt` | the window; withdrawal is always allowed |
| `questions` | dietary, access needs…; answers are read by the hosts only and deleted `answers_retention_days` after the event |
| `codeOfConduct` | `url` + `sha256`; registration needs the acknowledgement of exactly that text |

A member **withdraws** whenever they like (`vtc/events/registrations/withdraw`), even after
registrations close. A registration a host declined or removed is not re-opened by the
registrant.

## Privacy

The **roster setting** is chosen when the event is created and **fixed when it is
published**: `visible` (registrants going or maybe see each other) or `hidden` (only hosts
see who is coming). Every registration records the setting it was made under. A count is
shown to non-hosts only with `showCount`, and below `countThreshold` (default 5) as "fewer
than". **Where it happens** — places, join links, door codes — is released by
`vtc/events/access/show` only to registrants who are going, from `revealAt` if set, unless
the host marks it public. The community sends no reminders: the hosts suggest them, and the
member's own agent fires them.

## Configuration

```toml
[events]
enabled = true                # off: every event read is notFound, every change eventsOff
reports_per_day = 10          # vtc/events/report, per member
answers_retention_days = 30   # registration answers kept after an event ends
```

The community's `events` policy (Rego, purpose `events`, package `vtc.events`) is asked on
create, update and publish, after the community's own checks, and may only refuse. The
shipped default allows; see `vtc-service/policies/default/events.rego` for its input.

## Reports

Any member of an event's audience may report it once (`vtc/events/report`), within the
daily limit. Reports are kept in the `events` keyspace by reference; surfacing them on the
administrators' action list is the next step of this programme.

## Departure

When a member leaves, their registrations still in play are removed (freeing places for the
waitlist), and a purge erases their answers. Their host appointments go with their
access-control entry.
