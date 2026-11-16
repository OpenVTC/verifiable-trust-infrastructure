---
name: vtc-community
description: Work with a Verifiable Trust Community (VTC) through the vtc-mcp bridge — configure and run a community as an administrator, or act and read as a member. Use when the user asks to set up or manage groups, boards, elections or polls, data rooms, the member directory, members and join requests, roles and access, or to see what a community is doing, and a vtc-mcp server is available. Not for a VTA (keys, vault, contexts): that is vta-mcp.
---

# Working with a community through vtc-mcp

You are driving a Verifiable Trust Community through the `vtc-mcp` MCP
server. Every tool call is one signed Trust Task sent as **one identity** —
a member's persona, or a dedicated agent entry an administrator enrolled —
and **the community decides**. The bridge's own policy may refuse a step or
ask the operator to confirm it. Nothing you do here grants access.

## Start every session the same way

0. If `vtc_status` shows no `signedInAs` and the person wants to act as
   themselves, `vtc_sign_in` (audience `member`, or `admin` for the console),
   show them the trigger link, then `vtc_sign_in_finish`: it answers with a
   match number for them to compare in their wallet, then with the session.
   Never approve on their behalf, and never describe the number as anything
   but theirs to compare. For administrative work, `vtc_enrol_signing_key`
   with no arguments names the bridge's key; the person signs the
   authorization in the console (*Console signing keys → Authorize another
   key*, through their wallet) or with `cnm access authorize-key`. Called again
   with the JSON or the saved file, the bridge acts with their administrative
   standing. A result with `status: "stepUpRequired"` carries
   a `link`: show it to the person (a QR code is fine), tell them it expires
   at `linkExpiresAt` and that their wallet will show exactly what will be
   done, and resend the identical call only after they say they approved.
   Never call it approved yourself. A refusal asking for a step-up with no
   link, or for an approval, is theirs to answer in the console, wallet or
   `cnm` — say so, and resend the same call only after they have.
1. `vtc_status` — connected? as whom? over which transport? what policy?
   `connected: false` with a `transportHealth.lastFailure` means the last
   call could not reach the community; retry once before reporting it.
2. `vtc_whoami` — what the community knows of this identity (it may answer
   only the configured identity, with the community's reason).
3. `vtc_supported_tasks` — what this community serves; after it, the catalog
   marks each operation served or not.

## Find, then send

- `vtc_list_operations` is the catalog: every operation, its description
  from the specification, its risk class, and this bridge's policy decision.
  Narrow with a slug glob (`vtc/groups/*`). Ask for `detail: "full"` to get
  an operation's **payload schema and declared error codes** before building
  a call — never guess a payload shape.
- `vtc_call` sends one operation by Type URI. An unset optional member is
  **absent**, never `null`.
- For a multi-step job use the matching prompt or workflow tool:

| Job | Prompt (the brief) | Tool (does it, one guarded step at a time) |
|---|---|---|
| Set up a group | `setup-group` | `group_setup` |
| Create a board | `create-board` | `board_create` |
| Run an election or poll | `run-election` | `election_create` |
| Open a data room | `open-data-room` | `room_open` |
| Admit a member | `admit-member` | `member_admit` |
| Grant administration | `grant-administration` | `admin_grant` |
| Create a member badge | `create-badge` | `badge_create` |
| A member's own badges | `my-badges` | — (`vtc_call`, signed in as the member) |

A workflow tool stops at the first step that is refused or parked and
reports how far it got; continue from there with `vtc_call`.

## Parked is not failed

A result with `status: "parked"` means the community needs other
administrators' approval. **Do not resend.** Report the action id, and follow
it with `vtc_actions_show`. Approving someone else's action with
`vtc_actions_decide` always asks the operator to confirm against the verified
summary and the match code; never present a decision as made until the
response says so.

## Read the guide first

The community's own operator guides are resources: `vtc://guide/groups`,
`boards`, `elections`, `rooms`, `rooms-quickstart`, `admission`, `lifecycle`,
`vetting`, `directory`, `admin-access`, `badges`. Read the one for the job before the
first write; the prompts name which.

## Rules

- Report a refusal with the community's own code and message; do not retry a
  refused or parked step on your own.
- A member's personal text (a label, a note, a card value) stays out of
  summaries and logs beyond what the task needs.
- Identifiers: a group is `grp_…`, a directory entry `dir_…`, a board
  `brd_…`; members in group and board tasks are named by **directory entry
  id**, not DID — find them with `vtc/directory/entries/*`.
- Members take election tickets and cast through their **own** VTA and
  wallet; the community, and this bridge, never see a ballot.
