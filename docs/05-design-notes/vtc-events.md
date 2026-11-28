# VTC events, meetings and the member's calendar: design

Status: **proposed, design only**. No specification, task family or code exists yet. Per the
spec-first rule, nothing here is implemented before (1) a VTI specification chapter
(proposed `spec/12e-vtc-events.md`, requirements `VTI-EVT-*`) and the notification kind
`event` (`spec/05a-notifications.md` and Appendix G) are merged in dtgwg-vti-spec, and (2) the
task families `specs/vtc/events/*/0.1` and `specs/vta/calendar/*/0.1` are merged in
dtgwg-trust-tasks-tf and pinned (`vti-specs-vtc`, `vti-specs-vta`).

Decisions 1, 3, 10 and 16, the roster setting, and the phase order were settled with the owner on
2026-11-27 (*Settled* below). The rest are recommendations that follow from the specification
or from how groups, badges, boards, rooms and notifications already work. Decisions 20 – 25
were added in a review pass and confirmed by the owner the same day. Decisions 26 and 27 are
recommendations awaiting confirmation.

**Phase 3 (the member's calendar) is implemented in the VTA**: all thirteen `vta/calendar/*/0.1`
tasks, sync, reminders, feeds, receipts and `export`, with `pnm calendar`
([`docs/02-vta/calendar.md`](../02-vta/calendar.md)). Still to come in the phase: the browser
plugin's and OpenVTC's views and the vta-mcp / vtc-mcp tools. Two requirements are not met
and are recorded as divergences: the event's own suggested reminders and places in a feed
(VTI-CAL-041; `EventRef` carries neither), and sending busy times (no `busy/put` task until
phase 7).

Mockups and the infographic (what it brings, how it works, user flows, seven screens):
<https://claude.ai/artifact/Fs3SHDdLRSXjdt5xXEzVYX>.

## What this is

A community holds **events**: a meetup, a workshop, a conference, an AGM, a social. Members see
the events they may come to, register, invite others, withdraw, get reminded, check in, and
afterwards find the notes, the recording and an attendance badge. A **meeting** is an event with
governance attached: an agenda, a chair, a roll call, a quorum, minutes, action items, and
motions decided by the community's existing voting.

A member belongs to many communities through one VTA. The VTA gives them **one calendar across
all of them**: every event they are registered for, every invitation they hold, their own
reminders, and an ICS feed for the calendar app they already use. Each community's portal gives
the **community view**: what is on there, and what they are going to.

Like badges and boards, an event **confers no authority** (VTI-VTC-020). Being registered, or
having attended, is never read by an authorization decision. It may be read by a *dynamic group
rule* (for example "attended five meetups"), which is how badges already count things.

## Prior art this design takes from

The research behind this note (2026-11-27) is summarised here so that later work does not
repeat it.

| Source | What we take |
|---|---|
| **JSCalendar 2.0** (draft-ietf-calext-jscalendarbis, in IESG evaluation; obsoletes RFC 8984) | The **stored and wire shape** of an event: `start` as local date-time + IANA `timeZone`, `duration`, `recurrenceRules` / `recurrenceOverrides` / `excludedRecurrenceRules`, `locations` / `virtualLocations` (`features`), `participants` with `roles` and `participationStatus`, `alerts`, `privacy`, `relatedTo`. The trust-tasks schemas take the JSCalendar member names verbatim, so conversion to iCalendar is the IETF's mapping (draft-ietf-calext-jscalendar-icalendar), not ours. |
| **iCalendar** RFC 5545, **7986** (CONFERENCE, IMAGE), **9073** (PARTICIPANT, VLOCATION, VRESOURCE, STRUCTURED-DATA), **9074** (alarm acknowledge / snooze) | Interop at the edges only: `.ics` download, ICS subscription feeds. Pitfalls to respect: overrides keyed by the *original* start (RECURRENCE-ID), "this and following" splits the series, all-day is a DATE, `UNTIL` in UTC, never floating time for a multi-party event. |
| **iTIP** RFC 5546 | The **state machine**, not the transport: the organiser is authoritative, a `sequence` increments on a significant change (time, place, recurrence) and replies carrying an older one are ignored, a reply carries only the replier's own status, a counter-proposal is a proposal the organiser accepts or declines. iMIP (email) has no sender authentication; our replies are signed Trust Tasks, which is the improvement. |
| **RFC 7953 VAVAILABILITY**, free/busy | Later: a member's bookable windows, and find-a-time answered by the member's VTA as coarse busy blocks, only to a party the member allows. |
| **JMAP Calendars** (RFC Editor queue) | The **sync pattern** for the VTA: `changes` since an opaque state token, rather than re-reading everything. |
| **schema.org** Event / EventSeries, **FEP-8a8e** (fediverse events) | Public events only: JSON-LD on the community's public website (`vtc/website/*`), `eventStatus` (cancelled / rescheduled / postponed). Federation is not proposed: ActivityPub RSVPs are public. |
| **Luma, Eventbrite, Meetup, Discord, Google / Outlook, Calendly / Cal.com, Doodle / Rallly** | The feature list in *Scope*: approval-required registration, capacity + waitlist with a claim window, plus-ones, registration questions, co-hosts, hidden guest lists, location revealed after approval, recurring series with per-occurrence RSVP, reminders, ICS feeds, check-in, polls to find a time, booking pages. |
| **OB3**, **OpenID4VP** (+ HAIP), **Bitstring Status List** | Tickets and attendance: an attendance badge is a badge (OB3, as `vtc/badges` already issues); door check-in can use the community's existing OpenID4VP verifier; a QR code carries a nonce, never the ticket. |

## Scope

The whole programme, phased below. Paid tickets are **out of scope** (no payment rail exists and
none is proposed).

**Booking pages** ("book a meeting with me", decision 28)
- A member publishes a page in a community where others book time with them: one or more
  meeting types (30 minutes, an hour), weekly available hours with date exceptions, buffers,
  minimum notice, how far ahead, a daily cap.
- Different rules per tier: members of the community (narrowed by group, badge or role), people
  known to the community (members of partner communities, holders of a relationship), and
  guests from outside.
- The host's other commitments, in this community and in others, block slots without anyone
  learning what they are.
- Booking, rescheduling and cancelling by the booker within the host's rules; approval where a
  tier needs it; the booking lands in both people's calendars with reminders and a receipt.

**Events**
- Create, edit, publish, postpone, reschedule, cancel, end, archive; drafts.
- Time: local start + IANA zone, duration or end, all-day, multi-day. Displayed in the viewer's
  zone with the organiser's zone beside it.
- Places: a physical location, an online link (any provider), or both (hybrid). The access
  details can be withheld until a registration is accepted, and until N hours before the start.
- Recurring series (a weekly meetup), with per-occurrence changes and per-occurrence or
  whole-series registration.
- Multi-session events (a conference): sessions, tracks, speakers, per-session capacity, the
  member's own agenda.
- Hosts and co-hosts; check-in staff; speakers (display only).

**Registration**
- Modes: `open`, `approval` (hosts decide), `invitation` (only the invited), `closed`.
- Capacity, a waitlist with automatic promotion and a claim window, a registration window.
- Plus-ones (a per-event limit).
- Registration questions (dietary, accessibility, a free-text note), each with who may read the
  answer, and a disclosure statement generated as the directory's is (VTI-DIR-130).
- States: `invited`, `going`, `maybe`, `declined`, `pending`, `waitlisted`, `offered` (a waitlist
  place to claim), `withdrawn` (the member), `removed` (a host), then `attended` / `noShow`.
- **Remove myself** is `vtc/events/registrations/withdraw`, always allowed, never parked.

**Invitations**
- A host invites named members.
- **Automatic invitation by policy**: an audience rule over groups (static, dynamic, badge
  groups), roles, credential-sourced directory fields and tenure, re-evaluated as membership
  changes, so a member who joins the group later is invited too.
- Invitation links (a trigger link, VTI-LNK, with a code stored only as a digest, as badge claim
  codes are) for passing an invitation hand to hand.
- Members may invite other members where the event allows it ("bring a friend").

**Privacy (per event)**
- Who may see the event exists: `listed` (everyone the audience covers), `unlisted` (only with
  the link or an invitation), `invitees` (only those invited).
- **The roster setting**: `visible` (registrants see who else is coming) or `hidden` (no
  attendee sees anyone else). Whether a **count** is shown, and a threshold below which it
  reads "fewer than k", is set alongside. See decision 16.
- **Anonymous registration** (set with the roster setting, and implying `hidden`): the hosts
  and the community also see only a count. The member proves they may come without saying who
  they are (decision 17).
- Without anonymous registration, hosts see the whole roster and the community holds it, so
  `hidden` means *other attendees* cannot see it.

**Things attached to an event**
- A **data room** for the agenda, notes, files, slides, recordings and chat.
- A **board** for questions and topics (an AMA, an unconference's session vote).
- **Elections** for a meeting's motions.
- An **attendance badge**, given at check-in or by a claim code at the door.
- A **feedback form** afterwards (later).

**Meetings**
- Agenda items (ordered, an owner, a time box, links to board ideas or room files).
- A chair and a secretary; a roll call from check-in.
- A quorum rule (a count or fraction of the meeting's roster, optionally by role), shown live,
  which gates whether a motion may be opened.
- Motions opened as elections from the meeting, using the existing voting.
- Minutes, recorded in the meeting's room, approved by the chair.
- Action items with an assignee and a due date, which appear in the assignee's calendar.
- Finding a time: a **poll** of candidate slots (yes / if need be / no), with hidden voters
  optional, closed into an event.

**Reminders and alerts**
- Changes: rescheduled, moved, cancelled, waitlist place offered, registration accepted.
- Reminders before the start, at offsets the organiser suggests and the member may override,
  per event or by default.
- Delivered to the member's devices through their VTA and mediator; titles never go through a
  third-party push service.

**Views**
- **The member's calendar in their VTA**, across communities: agenda, day, week and month views,
  conflicts across communities marked, invitations to answer, action items due.
- **The community view** in the member portal: upcoming events, filtered by group; mine;
  invitations; the calendar.
- **The console**: create and edit, the roster, the approval queue (on the action list), check-in
  mode, attendance and counts.
- `.ics` download per event; a private ICS feed for the member's calendar app; a public ICS feed
  and public event pages for a community's public events.
- MCP tools: "what's on this week", "register me", "what's on my agenda" (vtc-mcp, vta-mcp).

## The decisions

1. **One family, two kinds.** An event has `kind: event | meeting`. A meeting is an event with
   the governance members (agenda, chair, quorum, minutes, action items, motions) allowed. One
   family keeps registration, privacy, reminders, rooms and the calendar written once. Tasks that
   only mean something for a meeting refuse on an event.

2. **An event's own identity is optional.** By default an event belongs to the community and
   has no DID: there can be hundreds (a weekly meetup), and minting and hosting a DID for each is
   waste. What such an event issues (a ticket, an attendance badge) is issued **as the
   community**, as badges have been since dtgwg-vti-spec #110.

   A host may give an event **its own identity** (`identity: true`, fixed at creation). The
   community's VTA mints a `did:webvh` from a new `vtc-event` DID template, as groups are minted
   from `vtc-group`. The community issues the event an authority credential, and revoking that
   credential voids everything the event issued (the group pattern, VTI-DIR-100 – 105). An event
   with an identity:
   - issues tickets and attendance credentials **as itself**, endorsed by the community, so an
     outside verifier at the door can check them without knowing the community;
   - is a messaging party: it advertises TSP and DIDComm, so **guests who are not members** and
     **partner communities** can address the event directly (decisions 18, 19);
   - has a public profile (name, picture, website page) that outlives the community's listing.

   It suits a conference, a long-running series, or an event co-hosted with other communities.
   A series takes one identity for the series, never one per occurrence. Hosting the DID uses
   the community's existing `dids.webvh_server` setting.

3. **The roster is the event's own, never a community group**, with or without an identity. The
   badge design made a badge a group because a badge is long-lived and holds credentials. An
   event's roster is short-lived, has states a group cannot express (waitlisted, offered, maybe,
   checked in), and must not appear in `vtc/groups/*` or the directory's `sharedGroups`. So the
   roster is its own record. Two places that today accept only a group learn to accept an event
   roster:
   - a room binding (`groups::bindings::RoomBinding`) gains a source `event:<id>` whose members
     are the `going` (and, by setting, `maybe`) registrants, so the event's room admits and
     removes people as the roster changes, with the reconciler and renewal it already has;
   - a board's audience (`BoardAudience`) gains `Event { event_id }`.

4. **Who may come is a rule, and the rule is the dynamic-group rule.** An event's `audience` is
   `members`, a list of groups (which covers badges, since a badge is a group), a role, or a rule
   in the dynamic-group language (`groups::dynamic`, `{"all":[...]}`). The rule language gains one
   fact, **`group`** (`{"fact":"group","op":"oneOf","values":[<group ids>]}`), which closes a gap
   groups have too (a dynamic group cannot today say "member of group X"), and one count fact,
   **`eventsAttended`** (`atLeast`), for badges like "came to five meetups". The rule is checked
   when the member opens or registers, as an election's roll is (VTI-NTF-004): an invitation is
   never evidence of eligibility.

5. **Automatic invitation is the audience plus a mode.** `invite: none | notify | expect`:
   - `none`: the event is listed to its audience; members register themselves.
   - `notify`: every member the audience covers is sent an invitation (the `event` notification
     kind), and a member who comes into the audience later is sent one then.
   - `expect`: as `notify`, and each is recorded `invited` with a response expected (a staff
     meeting). Nobody is ever recorded `going` without their own act.
   A member can opt out of a *series* or of everything from one *calendar*, as `gopt:` opts a
   member out of a dynamic group; the rule never overrides it. An events sweeper owns sending,
   on the election notice's pattern (`notifications::election`): a durable row first, the sweeper
   the one sender, an idempotent notification id and revision.

6. **A community-wide events policy narrows, never widens.** A new `PolicyPurpose::Events`
   (Rego, refuse-only, like `Groups`) lets a community say, for example: only administrators
   create `listed` events for everyone; a group's managers create events only for their group;
   `expect` needs an administrator; capacity above 500 needs approval. Hosts choose within it.

7. **Capabilities.** `Capability::EventsManage` (`vtc.events.manage`) with resource qualifiers:
   - `event:<id>`: hosting one event (co-hosts are appointed exactly as group managers and board
     facilitators are, through `acl::appointment`);
   - `group:<id>`: creating events whose audience is that group, so a group's managers can run
     their group's calendar without an administrative role;
   - unqualified: any event.
   `Capability::EventsCheckIn` (`vtc.events.checkin`, qualified `event:<id>`) is the door staff's
   grant: check people in, see names, nothing else. Members' own acts (register, withdraw, invite
   where allowed, answer a poll, set their reminders) need no capability and join
   `PORTAL_SIGNING_SCOPE`.

8. **Notifications carry no content; the agent opens what the member chose.** The notification
   kind `event` (to be defined in 05a and registered in Appendix G) names the community as holder,
   the event's id, the operation `vtc/events/show`, the audience and the event's period, and
   carries nothing else (VTI-NTF-003: not the title). It is revised on a change of time
   (`sequence` up) and withdrawn on cancellation (VTI-NTF-024). It may be relayed by a partner
   community or network, which is how a co-hosted event reaches another community's members
   (VTI-NTF-040 – 047). Because a notification is only a pointer, the member's calendar has two
   tiers:
   - **notified**: community, period and "an event you may come to", until the member opens it;
   - **mine**: events the member opened or registered for, which the VTA reads in full.

9. **The member's VTA reads their events, as their member identity.** The membership DID's keys
   are in the VTA, so the VTA can ask each community `vtc/events/mine/list` (with a sync state
   token, after JMAP) signed as that member. This tells the community nothing it does not
   already know: who its members are and what they registered for. No notification is needed for
   events the member registered for in the portal; the VTA's sync finds them. Sync is on by the
   member's standing choice per trust context, and VTI-NTF-053 is kept: the VTA never *opens* a
   merely notified event on its own.

10. **Reminders are fired by the member's VTA, not sent by the community.** The event carries the
    organiser's suggested alerts (`alerts`, e.g. 1 day and 1 hour before); the VTA schedules them
    for the member's own events, the member overrides per event or by default, and the VTA wakes
    the member's devices through the mediator as it already does for held notifications. The
    community never learns who wants reminders, the push path carries no title, and one
    implementation covers every community. Changes (rescheduled, cancelled, a waitlist place
    offered) are the community's to send, as notification revisions, because only it knows they
    happened. *Fallback:* a member with no device the VTA can wake gets reminders in the portal's
    home attention items.

11. **Access details are released, not published.** Location and join link live in a separate
    record read by `vtc/events/access/show`, answered only to a registrant in `going` (and only
    from `revealAt` if set). They never appear in `show`, `list`, notifications, ICS feeds or
    public pages unless the host marks them public.

12. **Check-in proves the registration live.** Phase one: the door's device shows a QR code
    carrying a fresh nonce; the member's wallet answers with a signed `registrations/check-in`
    over it. The community holds the roster and checks it live, so the default needs no
    credential. **Ticket credentials** are an option per event, for an offline door, a door run
    by another party, or a guest who is not a member. A ticket is issued on acceptance (by the
    event's identity if it has one, or else by the community), names the registrant's DID, and
    is valid until the event ends. It is revoked through the community's shared status set: a
    per-event set would single out a small event's attendees (VTI-CRD-014). It is checked by the
    community's OpenID4VP verifier, with a nonce per presentation and a used-ticket record per
    event so a ticket admits once. Check-in records `attended`, feeds the roll call and quorum,
    increments `eventsAttended`, and, if the event names one, offers its attendance badge (the
    member accepts, as every badge award is accepted: `vtc-badges.md` decision 2).

13. **Recurrence is JSCalendar's, stored as local time.** A series stores its rule and its
    overrides keyed by the original start; occurrences are expanded on read within a window,
    never stored ahead. Times are stored as local time + IANA zone and turned into instants on
    read, so a change in a country's daylight-saving rules moves nothing a member chose.
    "This and following" ends the series and starts a new one linked by `relatedTo`.

14. **ICS is a foreign protocol, so its routes are declared REST exceptions.** A calendar app
    cannot send a Trust Task. The VTA's private feed and a community's public feed are `GET` routes
    serving `text/calendar`, each a row in `REST_EXCEPTIONS` (VTA) and its VTC counterpart. A
    private feed URL is a bearer token: one per purpose, revocable, expiring, last-fetched shown to
    the member, and by default **titles and times only** (no access details, no attendees, no
    member identifiers in UIDs). Managing feeds is a Trust Task.

15. **Retention.** Registration answers and check-in records are deleted a community-set period
    after the event ends (default 30 days); the attendance count and `eventsAttended` survive.
    Audit records the acts (vtc-audit), not the answers.

16. **The roster setting is set once and shown before anyone registers.** `roster: visible |
    hidden` (and `anonymous`, decision 17) is chosen when the event is created and **cannot be
    changed after it is published**. An `update` that changes it is refused, not parked. The
    setting is shown on the event page, in `show`, and on the registration form, and each
    registration records the setting it was made under. A member who registered for a `hidden`
    event can never find themselves on a visible list. To change the setting, a host cancels the
    event and creates a new one, and every registrant is told and registers again by their own
    choice.
    - `visible`: registrants in `going` (and `maybe`) see each other. The audience sees the
      count, subject to the threshold.
    - `hidden`: no attendee sees another. Hosts and door staff see the roster.
    A member **cannot hide themselves** on a `visible` roster (settled 2026-11-27): a visible
    list that silently omits people is not what the setting promised the others. A member who
    does not want to be recognised registers under **another persona DID** instead (decision
    17). They appear on the roster as that persona, and the roster stays complete.

17. **Anonymous and persona registration use the PCS engine.** The owner asked on 2026-11-27
    whether the predicate credential system the community already runs for hidden vetting
    (`vti-vetting-pcs`, `vta/pcs/*`, the member's VTA as the engine) fits here. It does, and
    better than the voting registrar's tickets this decision first proposed. It already has
    the three pieces:
    - a **class credential**: the community issues a member a PCS credential for a class, and
      the member later proves in zero knowledge that they hold one, without showing which
      member they are;
    - a **tag**: a value derived from the member's PCS key and a scope. It is the same every
      time for one member in one scope and unlinkable between scopes, and it comes with a proof
      that it was derived correctly. Hidden vetting uses it so one vetter cannot count twice;
    - **withdrawal by tag**: a proof of knowledge of the key behind a tag, which exists today
      for withdrawing a vetting statement.

    To register, the member's VTA proves "I hold a credential in a class this event's audience
    names" and gives its tag for the scope of this event. The tag is the registration's
    identifier: one per member per event. The same member can change, withdraw or check in (the
    proof bound to the door's nonce) by proving the tag again, and nothing links their tags at
    two events. A voting ticket is spent once and cannot be changed or withdrawn, which is why
    it fits worse.

    Two uses:
    - **Anonymous events** (`roster: anonymous`): every registration is a proof and a tag. The
      hosts and the community hold tags and a count, and no membership DID.
    - **Persona registration** on any other event: the member registers under a persona DID of
      their choosing, with the proof. The roster shows the persona, and neither hosts nor
      attendees learn which member it is. An event may require identified registration
      (`identified: true`), and then refuses a persona: a meeting whose quorum counts members
      by role, or one with `invite: expect`.

    Consequences, stated on the event page: no approval by name, no questions that identify,
    attendance does not count toward `eventsAttended` (decision 26), and an attendance badge
    goes to the persona or not at all.

    The phase-0 spike is now against `vti-vetting-pcs`, and must settle:
    - **classes**: one per community membership and one per group, re-issued as dynamic
      membership changes. A rule fact that is not a class (tenure, a credential-sourced field)
      cannot be proven this way unless the community issues a class for it;
    - **revocation**: an epoch in the class label, as vetter classes use;
    - **transport**: a registration sent over the member's own mediator session identifies
      them, so it needs a sessionless door and a pause, as a ballot cast has (VTI-VOT-004);
    - **small audiences**: a proof among three members hides little, so `anonymous` is refused
      below a floor (10 proposed), and the event page states the size of the set;
    - **review**: the engine was built and reviewed for vetting; this is a new use of it.

18. **Guests who are not members.** An event may admit guests (`guests: none | invited |
    open`). A guest is any DID that signs in with a wallet (the `auth/oob/*` wallet sign-in the
    portal already uses) and registers. A guest never becomes a member, never sees the
    directory, and is never in a group. They see the event, its access details once accepted,
    and its room if the host extends the room to guests. With an event identity, guests address
    the event's DID directly. Without one, they use the community's wallet sign-in. The audience
    rule never admits a guest. Hosts admit guests by invitation (`invited`) or let any signed-in
    DID register (`open`, which an `Events` policy may forbid). Guests count against capacity,
    and their tickets (decision 12) are how an outside door checks them.

19. **Cross-community events.** A community co-hosts an event with partner communities or
    publishes it to a network:
    - **Reach**: the `event` notification, relayable (decision 8), goes to each partner
      community. The partner's administrator relays it to a selection of their own members
      (`vtc/notifications/relay`, `NotificationsRelay`), and the partner learns nothing about the
      host's members, nor the host about the partner's.
    - **Eligibility**: the audience can name a partner by its DID, and a member of the partner
      proves eligibility by presenting their partner membership credential at `show` or
      `register`, as a credential roll does for elections (VTI-VOT-016).
    - **Co-hosts**: a co-hosting community's members may hold `event:<id>` grants only if the
      event has its own identity. The grant is then held at the event, and nothing in the
      partner's ACL changes.
    - **One record**: the event lives at its holder, and partners never copy it. Their portals
      list it from the held notification and open it at the holder.

20. **Calendars.** Every event sits in exactly one **calendar**: the community's
    own, or a group's. A calendar is the unit a member follows, mutes or opts out of
    (decision 5), the unit a public ICS feed and a website page publish, and the natural scope
    of a host's grant: `vtc.events.manage` qualified `group:<id>` is the right to run that
    group's calendar. A calendar is a small record (name, colour, owning group, default roster
    setting and default reminders for new events), not a new authority.

21. **The member keeps the proof.** The community's signed reply to `register`,
    `withdraw` and `check-in` is the member's **receipt**: it names the event, the event's
    `sequence`, the registration's state and the roster setting it was made under. The member's
    VTA keeps each receipt beside the event in the *mine* tier. Nothing new is signed for this:
    a Trust Task reply is already a signed document. The consequence is the ownership property
    this design is for: a member's event history, receipts and attendance badges stay in their
    VTA when they leave a community, or when the community is gone, and `vta/calendar/export`
    hands them the lot (ICS plus the receipts) at any time. A receipt is evidence of what the
    community said, never authority (VTI-VTC-020).

22. **Announcements.** Hosts post announcements to an event ("bring a laptop",
    "we start 15 minutes late"). An announcement is a record on the event, read with
    `vtc/events/announcements/list` by registrants only. It reaches members as a **revision of
    the event notification**, which still carries no content (VTI-NTF-003): the member's VTA
    sees the revision, syncs, and shows the announcement from the event. A change of time is a
    `sequence` change, never an announcement, so calendars cannot drift from what a host wrote
    in prose.

23. **Code of conduct and accessibility.** An event may require the registrant to
    acknowledge the community's code of conduct; the acknowledgement is recorded on the
    registration and named in the receipt. Accessibility is structured, not free text:
    step-free access, captions, a hearing loop, a quiet space, a remote option. The fields are
    shown on the event page and usable as a filter in the community view.

24. **Events hosted by a person.** The notification model already allows any identifier as a
    thing's holder. A member's own VTA holds a small event (a dinner, a study group) and invites
    their contacts, with the same registration, roster setting and reminders, and no community
    involved at all. This is the far end of "we own our own events". It is its own family
    (`vta/events/*`, a subset of `vtc/events/*`: no audience rule, no policy, no groups; the
    audience is the contacts the host names) and its own phase (7). Two things the chapter must
    state: a personal VTA serving inbound registrations charges them to the budget for senders
    without standing (VTI-TRN-029), and it accepts a registration only from a contact the
    principal invited.

25. **Abuse limits.** Member-sent invitations are rate-limited per member per day
    by the `Events` policy, an invitation link has a maximum number of uses, and any member may
    report an event, which puts it on the administrators' action list. `guests: open` events are
    always subject to the community's operation budgets (VTI-TRN-029) for senders without
    standing.

26. **What counts as attendance** *(recommended)*. `eventsAttended` is a count of **check-ins**,
    never of registrations, and the party that decides what counts is the one writing the rule,
    not the host of each event:
    - The fact takes a scope and a window:
      `{"fact":"eventsAttended","calendar":"<id>","within":"P1Y","atLeast":5}`. A "Build Night
      regular" badge counts that calendar's events in the last year. Without `calendar` it
      counts every counting event in the community.
    - An event counts by default. A host may mark one `countsAttendance: false` (a private
      social), and a calendar sets the default for its events.
    - One event counts once: an occurrence of a series is one event, and a multi-session event
      is one event however many sessions the member attended.
    - A check-in at the door or by a host counts. A **self** check-in (an online event with no
      door) counts only where the calendar allows it, because it is the weakest evidence.
    - Guests, personas and anonymous registrations never count: there is no member to count
      for (decision 17).
    - Check-in records are deleted on the retention schedule (decision 15), so the count is
      its own small record: per member and calendar, a count per month. That is the least
      that answers a windowed rule, and the member can read their own.

27. **Rooms and boards follow the roster, and "maybe" stays outside** *(recommended)*.
    - **A shared room shows its members to each other.** A data room is an MLS group, so
      admitting attendees to one room tells each who the others are. On a `visible` event that
      is the setting working. On a `hidden` or `anonymous` event it would break the promise, so
      there is **no shared attendee room**: materials (slides, the agenda, files) are released
      to each accepted attendee as access details are (decision 11), and hosts post
      announcements (decision 22). A host who wants discussion on a hidden event may offer an
      opt-in room, entered by each attendee's own choice under a persona, with the event page
      saying that people in it see each other.
    - **A board on a hidden or anonymous event takes posts without names**, or is not attached.
    - **`maybe` is not admitted to the room by default.** Admission adds a member to the MLS
      group and issues them a room credential, and `maybe` changes more often than `going`, so
      admitting it churns the group. It also puts people who may never come in front of the
      attendees. The agenda and the event's description are on the event itself, which `maybe`
      can read. A host may set `roomAdmits: goingAndMaybe` on a `visible` event (a planning
      meeting where the undecided should read along).
    - **When**: admitted on becoming `going` (accepted, not pending or waitlisted), removed on
      withdrawal or removal. After the event the room stays open to those who were `going`
      until it is archived on the retention schedule; no-shows are not removed, since removing
      them would announce who did not come.

28. **Booking pages: "book a meeting with me"** *(proposed, 2026-11-27)*. A Calendly-like
    service inside the community, built from what events already are.
    - **The page.** A member (the *host*) creates a booking page in a community they belong
      to: a name, a description, and one or more **meeting types**, each with a length, a
      place (online link, in person, phone, released like access details, decision 11), its
      own questions, and **availability**: weekly windows in the host's IANA zone with date
      exceptions (RFC 7953 VAVAILABILITY's shape), buffers before and after, minimum notice,
      how far ahead, a daily cap, and a per-booker limit. A page may be personal or a
      **team** page over several hosts (round-robin or everyone), later.
    - **Tiers.** Each meeting type says, per tier, whether the tier may book at all, which
      windows it sees, its notice and horizon, whether a booking needs the host's approval,
      and its limit:
      - `members`: active members, optionally narrowed by the event audience language
        (groups, so badges; roles; a rule) — the same check as VTI-EVT-020;
      - `known`: people the community knows without their being members — members of a
        partner community or network proving it by credential (as decision 19), or a party
        with a relationship in force with the community;
      - `guests`: anyone signing in with a wallet (decision 18), approval on by default,
        always under the budget for senders without standing (VTI-TRN-029). A guest needs a
        DID; e-mail-only booking is out of scope.
      A booker is placed in the most trusted tier they prove, never one they assert.
    - **Busy without disclosure.** The free slots offered are the host's windows minus their
      bookings and events at this community, and minus **busy blocks their own VTA supplies**:
      at the host's standing choice, the VTA computes coarse busy intervals (rounded to 15
      minutes, no titles, no communities) from the host's calendar across every community
      (`vta/calendar/*`, phase 3) and pushes them to the page. The community learns only
      "busy then"; the booker learns only which slots are free. Without the VTA's blocks the
      page still works from what this community knows.
    - **A booking is an event.** Booking creates a `meeting` event in the host's calendar
      (unlisted, roster hidden, audience the two parties, the host as its host) with the
      booker registered `going` (or `pending` where the tier needs approval). Everything else
      comes free: access details released on acceptance, the receipt (decision 21), reminders
      fired by each party's VTA (decision 10), both parties' calendars via `mine/list`,
      cancellation and the `sequence` on a change. Rescheduling is the booker moving their
      own booking to another free slot, within the tier's minimum notice, answered with a new
      receipt.
    - **Holding a slot.** Two people may pick one slot together: `book` takes the slot under
      the events write lock and refuses the second with `slotTaken`, offering the next free
      slots. Nothing is held while a booker fills in the questions.
    - **Links.** A page has a stable link on the community's site (a trigger link,
      VTI-LNK, for the guest tier); a member's directory card may show "Book a meeting".
    - **Privacy.** The page never says why a slot is not free. A booker sees the host as the
      page presents them (its own name and picture, or the directory's projection for a
      member viewer). The host sees bookers' answers; nobody else does.
    - **Authority.** Any active member may create a page for themselves where the community's
      settings allow it (`events` policy may require a group, a role, or turn pages off).
      Nobody books themselves. A host's page goes when they leave the community, cancelling
      their future bookings with notice to the bookers.

## Storage (VTC)

A new keyspace `events` (`vtc-service/src/store/keyspaces.rs`, beside `BADGES`), backed up:

| Key | Record |
|---|---|
| `ev:<id>` | the event (JSCalendar-shaped), `sequence`, status, audience, invite mode, privacy, registration settings, attachments |
| `evx:<id>` | access details |
| `evr:<id>:<member>` / `mev:<member>:<id>` | a registration, and its index by member |
| `evw:<id>:<seq>` | waitlist order |
| `evi:<id>:<member>` | invitation sent (notification id, revision) |
| `evc:<digest>` | invitation-link code |
| `evo:<scope>:<member>` | opt-outs (series, calendar) |
| `evp:<poll>` / `evpv:<poll>:<member>` | scheduling polls and answers |
| `eva:<id>:<n>` | agenda items, action items (meetings) |

## The task families (draft)

`vtc/events/*/0.1`:

| Task | Who |
|---|---|
| `create`, `update`, `cancel`, `delete` (drafts only) | hosts (`vtc.events.manage`) |
| `show`, `list` (by range, calendar, group, `mine`), `changes` (sync state) | the audience |
| `mine/list` | the member, as themselves (the VTA's sync) |
| `access/show` | a `going` registrant |
| `registrations/register`, `registrations/update` (status, guests, answers), `registrations/withdraw` | the member |
| `registrations/list`, `registrations/decide`, `registrations/remove` | hosts; `list` filtered by the event's privacy for others |
| `registrations/check-in`, `checkin/challenge` | the member; door staff (`vtc.events.checkin`) |
| `invitations/send`, `invitations/list`, `invitations/links/create`, `invitations/links/revoke` | hosts; members where allowed |
| `hosts/appoint`, `hosts/remove`, `hosts/list` | as `vtc/groups/managers/*` |
| `attachments/add`, `attachments/remove` (room, board, election, badge) | hosts |
| `optouts/set`, `optouts/list` | the member |
| `agenda/update`, `minutes/record`, `minutes/approve`, `actions/{add,update,list}`, `quorum/show`, `motions/open` | meetings: chair, secretary, hosts |
| `polls/{create,show,answer,close}` | hosts; invitees answer |
| `booking-pages/{create,update,delete,show,list}` | a member for their own page; `show`/`list` the tiers a page admits (decision 28) |
| `booking-pages/slots/list` | a booker: the free slots their tier sees, for a range |
| `bookings/{book,reschedule,cancel,list}` | a booker for their own; the host for every booking on their page |
| `booking-pages/busy/put` | the host's own VTA: coarse busy intervals, replacing the last |
| `announcements/send`, `announcements/list` | hosts; registrants read (decision 22) |
| `calendars/{create,update,list}` | administrators, a group's managers; the audience lists (decision 20) |

`vta/calendar/*/0.1` (the member's VTA):

| Task | What |
|---|---|
| `list` | the agenda across every trust context the caller has authority in (VTI-NTF-051 holds: never across a context the caller cannot act in) |
| `sync` | pull `mine/list` / `changes` from each community now |
| `settings/{show,update}` | sync on/off per context, default alerts, quiet hours |
| `alerts/{set,clear}` | per-event overrides |
| `feeds/{create,list,revoke}` | private ICS feeds |
| `export` | the member's events and receipts, as ICS plus the signed replies (decision 21) |
| `busy/share` | at the member's standing choice per booking page, push coarse busy blocks to it (decision 28) |

Each new task gets a `vta_sdk::retry_safety` classification, a `schema_index` pin and a
conformance witness, as every family does.

## Integration map

| Existing | Used for |
|---|---|
| `groups::dynamic` rule language | the audience rule; gains `group` and `eventsAttended` |
| group managers, `acl::appointment` | co-hosts, door staff |
| `groups::bindings::RoomBinding` | the event's room, source `event:<id>` |
| community rooms (`vtc/rooms/community/*`) | agenda, notes, files, chat, minutes |
| boards (`BoardAudience`) | questions and topics, audience `Event` |
| elections / vti-voting | a meeting's motions; quorum gates opening |
| PCS engine (`vti-vetting-pcs`, `vta/pcs/*`) | anonymous and persona registration: class credential, tag per event |
| badges (+ claim codes) | attendance badges |
| notifications (`member_push`, election-notice pattern, relay) | invitations, changes, co-hosted events |
| VTA held notifications + device wake | the notified tier; reminders |
| directory audiences and disclosure statement | roster visibility; registration-question disclosure |
| action list (`admin_actions`) | registrations awaiting approval, polls to close, minutes to approve |
| `vtc/website/*` | public event pages with schema.org JSON-LD, public ICS |
| OpenID4VP verifier | the later ticket-credential check-in |
| vtc-mcp, vta-mcp | agenda and RSVP tools |
| pnm, the browser plugin, OpenVTC | the VTA calendar views (other repositories) |

## Phases

| Phase | Holds |
|---|---|
| **0 Specs and mockups** | VTI chapter `12e` (VTI-EVT-*); notification kind `event`; the `vtc-event` DID template; tt-tf `vtc/events/*` and `vta/calendar/*` 0.1; design canvas (portal calendar, event page with its roster setting, console editor and roster, VTA agenda). The anonymous-registration spike against `vti-vetting-pcs` starts here, because its result shapes the chapter. |
| **1 Events** | create / update / cancel / show / list, `kind: meeting` accepted; audience (members, groups, roles, rule with `group`); registration modes, capacity, waitlist, plus-ones, questions; withdraw; the roster setting, fixed at publish, and the count threshold; access details; hosts; `Events` policy; capabilities; portal and console pages; `.ics` download; audit; retention sweeper; calendars; code of conduct and accessibility fields; member invitation limits and reporting. |
| **2 Invitations, changes, other communities** | the `event` notification kind; `invite: notify / expect` with the re-evaluating sweeper; invitation links; revisions on reschedule, withdrawal on cancel, waitlist offers; opt-outs; **cross-community events**: relay to partners, partner members proving eligibility by credential; announcements. |
| **3 The member's calendar** | `vta/calendar/*`; sync from every community; VTA-fired reminders on devices; private ICS feeds; views in pnm, the plugin and OpenVTC; vta-mcp and vtc-mcp tools; receipts kept beside each event, and `export`. |
| **4 Identity, guests, tickets, the door** | optional **event identity** (`vtc-event` template, authority credential); **guests who are not members** (wallet sign-in, guest admission); **ticket credentials** and OpenID4VP check-in; check-in by nonce; `eventsAttended`; attendance badge offer; co-hosts held at the event's identity. |
| **5 Anonymous registration, recurrence** | registration by PCS proof and tag, and persona registration (decision 17); recurring series (overrides, this-and-following). |
| **6 Attachments and meetings** | event room via binding; board audience; agenda, chair, roll call, quorum, motions as elections, minutes, action items in the assignee's calendar; scheduling polls; public pages and public ICS on the community website. |
| **7 Booking pages** | "book a meeting with me" (decision 28): pages, meeting types, availability with exceptions, tiers for members, known parties and guests, free slots, book / reschedule / cancel, approval per tier, busy blocks from the host's VTA. Team pages (round-robin, everyone) after. |
| **8 Events hosted by a person** | `vta/events/*`: a member's VTA holds an event for their contacts (decision 24). |
| **9 Later** | multi-session events (sessions, tracks, speakers, personal agenda); find-a-time across several members' VTAs; bookable resources; feedback forms. |

## Settled (2026-11-27)

1. **A meeting is a kind of event**: one family (decision 1).
2. **An event's own identity is optional**, and the roster is always the event's own record
   (decisions 2, 3).
3. **Reminders are fired by the member's VTA**, with the portal as fallback (decision 10).
4. **The roster setting** is `visible` or `hidden`, chosen once, fixed at publish, and shown
   to attendees before they register (decision 16).
5. **Brought forward from "Later"**: guests who are not members, hiding the roster from hosts
   (anonymous registration), cross-community events, and ticket credentials (phases 2, 4, 5).

6. **A member cannot hide themselves on a visible roster**; they register under another
   persona DID instead (decisions 16, 17).
7. **Anonymous and persona registration use the PCS engine**, subject to the phase-0 spike
   (decision 17).
8. **Decisions 20 – 25 are confirmed**: calendars, receipts and export, announcements, code of
   conduct and accessibility, events hosted by a person (now phase 7), abuse limits.
9. **Paid tickets are out of scope.**

## Open

- Decisions 26 (what counts as attendance) and 27 (rooms follow the roster, `maybe` stays
  outside) are recommendations awaiting confirmation.
- The PCS spike's five questions (decision 17): classes, revocation, transport, the
  small-audience floor, review.
- Whether persona registration is allowed by default, with `identified: true` the exception
  (as written), or the other way round.

- What a cancelled occurrence of a series does to registrations for the series.
- The count threshold's default (5 is the usual k).
- Whether an action item is its own record or a room record the calendar reads.
- Booking pages (decision 28): which parties count as `known` beyond partner members and
  relationships; whether a guest's booking may ever skip approval; whether team pages come in
  phase 7 or after; whether a host's page may live in a community they do not belong to (as
  written, it may not).
