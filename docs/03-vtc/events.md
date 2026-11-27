# Community events

A community runs **events** — a meetup, a workshop, a social, an AGM — in **calendars**:
the community's own, and one per group that wants one. Members see the events their
audience admits, register, change or withdraw their registration, and the community answers
each change with a signed reply the member's own agent keeps as a receipt. Events carry no
authority: nothing about an event, a registration or an attendance is read by an
authorization decision.

Specification: the VTI Community Events chapter (VTI-EVT-001 – 135) and the `event`
notification kind (VTI-NTF-064 – 067). Wire: the `vtc/events/*` Trust Tasks — `create`,
`update`, `show`, `list`, `mine/list` and `registrations/*` at 0.2 (the 0.1 versions are no
longer served), the rest at 0.1. Design: [`vtc-events.md`](../05-design-notes/vtc-events.md),
which also describes the later phases (the member's calendar across communities in their VTA,
check-in and tickets, meetings, booking pages).

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

## Pages

**The console** (*Events*, shown to holders of `vtc.events.manage` at any qualifier): every
event the viewer runs, filtered by calendar, status and range; *Calendars* to make, change and
archive the community's and groups' calendars; the editor (time with an IANA zone picker,
place summary, access details with *public* and *release from*, audience by members, groups or
badges, or roles with an optional rule, registration settings, questions, code of conduct,
accessibility, the roster setting — offered on a draft with a warning that publishing locks it,
and shown fixed after — the count, listing and suggested reminders); *Publish*, *Cancel* with a
reason, *Delete draft*; *Registrations* (approve or decline pending, remove, waitlist positions,
guests and answers); *Invitations* (who is invited and how they answered, invite a member,
make and revoke links — the link is shown once, when made — and post announcements); *Hosts*
(appoint, remove). The editor also sets the invite mode, whether members may invite, and partner
communities. Signed with the console key only.

**The member portal** (`#/events`, a home tile and attention lines for registrations waiting on
the hosts or a place, and the next event within a week): *Upcoming*, *Mine* and *Month*, with
calendar chips, and *Invitations* (answer going, maybe or decline; undo an opt-out); each event in the viewer's own zone with the event's beside it, the roster
setting and the count as the event shows it. One event: register (going or maybe, guests,
answers, the code of conduct), change or withdraw, where it happens once going (or when it will
be released), who else is going on a visible roster only, *Add to calendar* (an `.ics` file
built in the browser from what the community answered — no route), the hosts' announcements,
*Don't invite me to this*, and *Report this event*. `#/events/join/<code>` redeems an invitation
link and offers the event.
Signed with the portal key the member delegated `vtc/events` to.

## Invitations

An invitation tells a member about an event; it never registers them. Each member has at most
one invitation per event, which carries their **answer** — `going` and `maybe` register them
(through the same checks as `registrations/register`), `decline` registers nothing, and a later
answer replaces an earlier one (`vtc/events/invitations/respond`, VTI-EVT-104).

- **The audience** (VTI-EVT-100 – 102): an event's `invite` is `none` (the default), `notify`
  or `expect` (a reply is expected). Once the event is published, the events sweeper invites
  every active member of the audience who is not registered, not yet invited and has not opted
  out, and keeps going as the audience grows.
- **Hosts and members** (`vtc/events/invitations/send`, VTI-EVT-103): a host invites any
  active member, even one outside the audience — the invitation lets them see the event and
  register. With `membersMayInvite`, a registered member may invite members of the audience.
  Within `[events] invitations_per_day` per inviter.
- **Links** (`vtc/events/invitations/links/*`, VTI-EVT-107): a host makes a link with a use
  limit and an expiry. Its code (256 random bits) is answered once by `create` and never again —
  the community keeps only its SHA-256 digest, and the response is not kept for a redelivery.
  An active member who redeems it is invited as a host would invite them. Every reason a code
  does not work (unknown, expired, used up, revoked, already used by this member) is the one
  `linkInvalid`. The portal's page for a link is `#/events/join/<code>`.
- **Opt-outs** (`vtc/events/optouts/{set,list}`, VTI-EVT-110): a member stops invitations to
  one event or from one calendar; the sweeper and members' invitations skip them. A host's
  invitation is not stopped by an opt-out from the audience.

Every invitation is delivered as an `event` **notification** to the member's DID (below).

## Notifications

The community originates the `event` kind (VTI-NTF-064 – 067), as it does `election`: the
notice row is written first, and the events sweeper is its only sender, through the durable
member push (`notifications::push_signed`). A notification names the community, the event id,
`vtc/events/show/0.2`, the audience (one member's DID, or a partner community's DID) and the
event's period — never its title, place, text or an announcement. A change of time or place
(the event's `sequence`) sends a new revision; cancelling, an invitation revoked, or the member
leaving the audience sends a withdrawal. Before each offering revision the sweeper re-checks
that the invitee is still an active member who may see the event. Membership, directory and
group changes kick the sweeper.

## Announcements

A host posts an announcement to an event's registrants (`vtc/events/announcements/send`,
VTI-EVT-120 – 122), within `[events] announcements_per_day` per event. Announcements never
change the time or place — the event's `sequence` is unchanged — but mark it changed, so a
member's agent reading `show` sees something new. Their text is never in a notification.
Hosts and live registrants read them with `announcements/list`; anyone else is
`notRegistered`.

## Partners

An event's audience may name **partner communities** (`audience.partners`, VTI-EVT-130 – 135):
each must be an active member party of this community holding a current membership credential,
or a counterparty in a relationship in force — else `partnerInvalid`. A partner community gets
one `event` notification at its own DID, to relay to its members as it decides. A partner's
member shows the event and registers by carrying a presentation of their membership of that
partner; it is verified **before** the event is looked up (the check `vtc/elections` uses), and
an unobtainable DID document or status list is the standard `indeterminate`, the same whatever
the event. A partner's member registers under their DID, is never on the roster (the roster
says only how many others are going), and receives no access detail they are not otherwise
entitled to.

## Configuration

```toml
[events]
enabled = true                # off: every event read is notFound, every change eventsOff
reports_per_day = 10          # vtc/events/report, per member
invitations_per_day = 20      # vtc/events/invitations/send, per inviter
announcements_per_day = 10    # vtc/events/announcements/send, per event
answers_retention_days = 30   # registration answers kept after an event ends
```

The community's `events` policy (Rego, purpose `events`, package `vtc.events`) is asked on
create, update and publish, after the community's own checks, and may only refuse. The
shipped default allows; see `vtc-service/policies/default/events.rego` for its input.

## Reports

Any member of an event's audience may report it once (`vtc/events/report`), within the
daily limit. Each reported event appears once on the administrators' action list (kind
`events.report.review`, decided by holders of `vtc.events.manage`), never naming who
reported it. **Cancel the event** upholds the reports: the event is cancelled as its hosts
would cancel it, and its registrants see it cancelled. **Dismiss report** closes them and
leaves the event. A later report raises a new item. The events sweeper re-raises any report
whose item was lost.

## Departure

When a member leaves, their registrations still in play are removed (freeing places for the
waitlist), and a purge erases their answers. Their host appointments go with their
access-control entry.
