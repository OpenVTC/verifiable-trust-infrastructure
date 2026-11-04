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

A deleted board's elections each keep a tombstone for a while (see *Deleting a board*):

```toml
[boards]
tombstone_retention = 365        # days; 0 keeps none; "forever" keeps them for good
```

## Who does what

| Who | Holds | May |
|---|---|---|
| Board creator | `vtc.boards.manage` **and** `vtc.elections.manage`, both unqualified | create boards, change a board's election template |
| Board manager | `vtc.boards.manage` unqualified (every `community-admin`) | everything a facilitator may, on every board, and delete a closed board |
| Facilitator | `vtc.boards.manage`, unqualified or `board:<boardId>` | change, close and archive the board — closing ends its voting; accept, decline, merge, reopen and select its ideas; hide notes |
| Member of the audience | an active member (and, for a group board, a member of that group) | propose, edit and withdraw their own ideas; add and withdraw their own notes; read the board |

`community-admin` holds `vtc.boards.manage` like every `vtc.*` capability. A facilitator for
one board is an entry whose capability scope lists `vtc.boards.manage` at `board:<boardId>`.
A facilitator who is not in the audience can run the board, but cannot propose to it.

Opening an election needs no `vtc.elections.manage` from the facilitator: the template was
fixed by someone who holds it, and it is never binding. Closing the board ends its elections
on that same authority (VTI-BRD-006). Otherwise, closing early, cancelling and certifying a
board's election still take `vtc.elections.manage` (VTI-BRD-032).

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
6. **Changing a board.** A facilitator changes the title, description, windows, topics,
   formats, limit, selection rule and timetable with `vtc/boards/update` — in the console, **Edit
   board** on the board's page. The audience and the voting window are fixed once voting has
   opened (`fixedAfterVotingOpens`), and a slot a selected idea is placed in stays. A change
   applies to ideas accepted after it: an idea already open for votes keeps the voting window its
   election was registered with, since a registered election's window cannot move.
7. **Close: voting ends.** `closed` takes no new ideas or notes and opens no election, and it
   ends the voting on every idea (VTI-BRD-006):
   - an election open for voting is **closed early**: the ballot box counts it as it stands, and
     that count is final;
   - one not yet open for voting, or not yet registered, is **cancelled**, and its idea is not
     selected;
   - one whose manifest does not allow closing early runs to the close its manifest states, and
     the close answers which ideas those are (`closing.runningToClose`). Every board election is
     opened allowing it now (VTI-BRD-030); only elections opened before this rule can't.

   The board is recorded closed first; each close or cancellation is recorded on its election,
   asked for at once, and asked again by the elections sweeper until the ballot box answers. The
   answer doesn't wait for the ballot box. Facilitators still decide and select afterwards.
8. **Archive.** `archived` takes no change at all, and hides the board from members.
9. **Delete.** A board manager deletes a closed or archived board once every election on it has
   closed or been cancelled (`vtc/boards/delete`, VTI-BRD-007), with a passkey gesture bound to
   the deletion. It removes the board, its ideas, its notes and each election's title,
   description, roll and ticket records. Each election keeps a **tombstone** — identifier,
   manifest digest and the board heads the community kept — for `[boards] tombstone_retention`
   (VTI-BRD-008), so a voter can still check a receipt against the community's record. The
   elections sweeper removes tombstones once their retention has passed; a retention of `0`
   keeps none. In the console: **Delete board** on a closed board.

   While it is kept, any active member or elections manager reads a tombstone with
   `vtc/elections/tombstones/show` (VTI-BRD-009) — `cnm elections tombstone <election-id>` — to
   check a receipt against the heads the community kept. Each head comes in the ballot box's own
   signed document, so the check does not rest on trusting the community. An unknown election,
   one the caller may not read and one whose tombstone has gone are answered alike
   (`electionUnknown`).

## From the command line

Facilitators use `cnm boards`, as the community's administrator. Members use `pnm boards`, signing
with their own VTA: the member's key never leaves it.

A facilitator starts from a template that `cnm` writes offline, edits it, and creates it:

```sh
cnm boards init --ballot-box <ballot-box-did> --title "Unconference" -o board.json
cnm boards create board.json
cnm boards show <board-id>
cnm boards decide <idea-id> accept            # opens the idea's election
cnm boards decide <idea-id> decline --reason "Covered in the keynote"
cnm boards decide <idea-id> merge --into <other-idea-id>
cnm boards select <idea-id> selected --slot <slot-id>
cnm boards close <board-id>                    # ends its voting
cnm boards delete <board-id> --reason "The event is over"   # closed boards only
```

`init --group <group-id>` puts the board to one group. Pick the ballot box from
`cnm elections ballot-boxes`. The written board already reads against `vtc/boards/create`.
`cnm boards notes`, `hide` and `unhide` moderate notes.

A member names the community and their membership DID on every command. `--entry` names the
vault entry to sign with, when more than one holds that membership:

```sh
pnm boards list --vtc https://vtc.example.com/v1 --vtc-did <community-did> --member <your-did>
pnm boards propose <board-id> --title "Rust in production" --description "War stories" …
pnm boards note <board-id> "I'd come to this" --idea <idea-id> …
pnm boards take-tickets <board-id> --context <context> …
pnm elections vote …                           # one idea at a time
```

`take-tickets` takes a ticket for every idea open for votes, each in its own request a few
seconds apart, so the community does not see one member's tickets arrive together.

## Departure and erasure

When a member leaves, their ideas still `proposed` are withdrawn, and the board shows the rest
as a former member's. When their records are erased, the text of their notes and of their ideas
no election carries is removed. An idea put to an election keeps its title and description,
because the election's manifest carries them and cannot change.

## Audit

`BoardChanged` rows cover board creation, changes, closing and deletion (with its reason and the
tombstone retention applied), every idea decision and selection, and hiding or showing a note.
Each election a closing ended writes its own `ElectionChanged` row (`closedEarly`,
`cancelled`), and so does each tombstone removed (`tombstoneRemoved`). They name ideas and notes by identifier, never their text, and never
anything about tickets or ballots. Opening an idea's election also writes the election's own
`ElectionChanged` row, as `vtc/elections/create` does.

## Storage

The `boards` keyspace, backed up. An accepted idea keeps only its election's identifier; where
the election stands is always read from the `elections` keyspace. A deleted board's tombstones
are `tombstone:<electionId>` rows in `elections`.
