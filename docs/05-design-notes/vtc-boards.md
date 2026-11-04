# VTC community boards: design

Status: **implemented** (`vtc/boards/*` 0.1). Specification: VTI Community Boards chapter
(VTI-BRD-001 – 080). Wire: trust-tasks-tf `specs/vtc/boards/*/0.1`. Operator guide:
[`docs/03-vtc/boards.md`](../03-vtc/boards.md).

## The decisions

1. **One election per idea, opened by a facilitator.** Members cannot create elections
   (`vtc.elections.manage`). The board's template is the authority instead: creating a board,
   or changing its template, takes `vtc.boards.manage` **and** `vtc.elections.manage`. A
   facilitator qualified to one board then opens elections only from that template, which is
   never binding (VTI-BRD-002, VTI-BRD-030). Accepting goes through
   `elections::ops::{check_create, create}` and is never parked.
2. **No second copy of election state.** An idea stores its election's identifier and when it
   was accepted, nothing more. `boards::view` derives `open`, `opening` with its refusal,
   cancelled → `notSelected`, `ballotsOnBoard` (the latest kept checkpoint's `treeSize`, public
   board, voting open) and the result from the election record on every read. Board elections
   are checkpointed every 30 minutes instead of 6 hours (`BOARD_CHECKPOINT_EVERY`) so the count
   moves.
3. **Ordering.** The election identifier is written on the idea **before** the election is
   created. A crash in between leaves an idea naming an election that does not exist, which reads
   as `proposed` and is accepted again. It never leaves an election no idea names. An election
   refused on first delivery is removed by `create`, and the idea keeps the refusal. The
   elections sweeper owns redelivery and records a later refusal on the election record.
4. **Results without certification.** Certification records an authoritative result and needs
   `vtc.elections.manage`. Facilitators need the result to select, so `elections::ops::verify`
   holds certify's items 3 – 9 (read the result, the head and every entry; audit the board from
   the community's own key). `certify` calls it before recording, and `verify_and_keep` keeps the
   verified result **uncertified** on the election record (`ElectionRecord::verified`). The
   elections sweeper runs it once for a board's election after voting closes and the final head
   is kept; `ideas/select` runs it on demand. A board shows `certified: false` until someone
   certifies.
5. **Never a ticket.** Neither the board's records nor its answers say whether anyone took a
   ticket or voted (VTI-BRD-033). The member portal asks the member's wallet for ticket state,
   as for any election.
6. **The portal key.** `vtc/boards` joins `PORTAL_SIGNING_SCOPE`. Member tasks accept a
   delegated document (`member_portal::delegation::accept`). Facilitator tasks resolve the
   signer through `member_signer` only, which never accepts it (VTI-BRD-051).

## Open

- **Appointing a facilitator who is not an administrator.** Today a qualified facilitator is an
  ACL entry whose capability scope lists `vtc.boards.manage` at `board:<id>`, which takes an
  administrative role. Groups solved the same need with `managers/add` (a resource grant).
  Boards have no such task yet; it needs a spec change.
- **Notes rate limit** is per process and in memory (10 per minute per author). It resets on
  restart and is not shared between replicas.
- **Anonymous proposals** and **batched tickets**: the chapter's two open issues.
