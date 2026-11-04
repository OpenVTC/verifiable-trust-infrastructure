# Community boards

A **board** is a shared space where a community's members propose ideas, leave notes, and vote
on each idea through an election of its own (`vtc/boards/*`, VTI-BRD-001 – 080). Think of an
unconference wall: members pin up session ideas, a facilitator puts the good ones to a show of
hands, and once the hands are counted the facilitator fills the timetable.

- **Ideas and notes are signed and attributed.** Everyone who can see the board sees who wrote
  what (VTI-BRD-070).
- **Voting is an ordinary election.** Accepting an idea opens one election for it from the
  board's template, through the community's normal elections ([elections.md](elections.md)).
  The board shows each election's stage, how many ballots are on its public board while voting
  is open, and its result once tallied. It never shows, and never records, who took a ticket or
  voted (VTI-BRD-033).
- **Results inform, facilitators decide.** Selecting an idea is a facilitator's decision with
  the result in view (VTI-BRD-040). It grants nothing (VTI-BRD-042).

## Turning it on

Boards need elections, so build with `voting` and configure `[voting]` exactly as
[elections.md](elections.md) describes. Without `voting` the tasks are served, but `create`
refuses every template (`templateInvalid`), because a board's ideas could not be put to a vote.

## Who does what

| Who | Holds | May |
|---|---|---|
| Board creator | `vtc.boards.manage` **and** `vtc.elections.manage`, both unqualified | create boards, change a board's election template |
| Facilitator | `vtc.boards.manage`, unqualified or `board:<boardId>` | change, close and archive the board; accept, decline, merge, reopen and select its ideas; hide notes |
| Member of the audience | an active member (and, for a group board, a member of that group) | propose, edit and withdraw their own ideas; add and withdraw their own notes; read the board |

`community-admin` holds `vtc.boards.manage` like every `vtc.*` capability. A facilitator for
one board is an entry whose capability scope lists `vtc.boards.manage` at `board:<boardId>`.
A facilitator who is not in the audience can run the board, but cannot propose to it.

Opening an election needs no `vtc.elections.manage` from the facilitator: the template was
fixed by someone who holds it, and it is never binding. Closing early, cancelling and
certifying a board's election still take `vtc.elections.manage` (VTI-BRD-032).

A facilitator does not decide their own idea while the board has another facilitator. If there
is none, they may, and the decision is marked `ownIdea` (VTI-BRD-013).

## The member portal

The portal signs a member's own acts (`ideas/propose|update|withdraw`, `notes/add|withdraw`,
and the reads) with its sign-in key, because `vtc/boards` is in the portal's `signingScope`.
Facilitators' acts never take that key (VTI-BRD-051). Tickets and ballots go through the
member's wallet, as for every election.

## A board's life

1. **Create.** Title, audience (`members` or one group), the proposal window, the voting window,
   optional topics, formats, a limit on ideas per member, a selection rule in plain words, a
   timetable of slots, and the **election template**: the question each idea's election asks,
   its secrecy, revote rule, board visibility and ballot box. The template is checked as
   `vtc/elections/create` would check a manifest.
2. **Proposals.** Members propose while the proposal window is open. An idea is `proposed`.
3. **Facilitation.** Accepting an idea opens its election (`board.<boardId>.<ideaId>`).
   Registration opens at once, so members can take their tickets ahead of voting, and voting
   runs for the board's voting window. Until the ballot box registers the election, the idea
   stays `proposed` and facilitators see `opening`. A refusal leaves it `proposed`, with the
   refusal code. Declining needs a reason the audience sees. Merging folds an idea into another
   live idea on the same board.
4. **Voting.** An open idea's election shows `ballotsOnBoard` from the latest board head the
   community kept, every 30 minutes while voting is open, for a public board only. Running
   totals are not shown.
5. **Selection.** Once voting closes, the community verifies the ballot box's published result
   from the board and its own voting key, the same checks certification runs, and keeps it on
   the election record **uncertified**. A facilitator then selects or does not select each idea,
   optionally into a timetable slot. The decision records the result's board head and whether it
   was certified. If it departs from the board's selection rule, it needs a reason.
6. **Close and archive.** `closed` takes no new ideas or notes; facilitators still decide.
   `archived` takes no change at all.

## Departure and erasure

When a member leaves, their ideas still `proposed` are withdrawn, and the board shows the rest
as a former member's. When their records are erased, the text of their notes and of their ideas
no election carries is removed. An idea put to an election keeps its title and description,
because the election's manifest carries them and cannot change.

## Audit

`BoardChanged` rows cover board creation and changes, every idea decision and selection, and
hiding or showing a note. They name ideas and notes by identifier, never their text, and never
anything about tickets or ballots. Opening an idea's election also writes the election's own
`ElectionChanged` row, as `vtc/elections/create` does.

## Storage

The `boards` keyspace, backed up. An accepted idea keeps only its election's identifier; where
the election stands is always read from the `elections` keyspace.
