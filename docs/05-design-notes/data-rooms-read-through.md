# Read-through: the agent as the room's memory

Status: **proposal for review, not a plan.** It works out the last unbuilt piece
of the rooms UI far enough to be argued with, and names one thing that has to be
decided before any of it is built.

It exists because two separate threads arrived at the same place. The **console**
cannot read a record, for a transport reason settled months ago. And
[`data-rooms-verified-reads.md`](data-rooms-verified-reads.md)'s commitment is
inert without a party that compares roots — which, it turns out, is the same
party. Building either one alone would build most of the other.

---

## 1. The gap, stated precisely

The browser console can create a room, admit members, list the rooms its wallet
holds keys for, and repair a member's history. It **cannot read a single
record**, and cannot write one.

The reason is not a missing feature. `manager/carrier.ts`'s `carrierParams`
passes exactly `{type, payload}` to the offscreen document, which then supplies
`vtaDid: active.conn.vtaDid` as the recipient. A `service` naming a **host** is
silently dropped, and the call lands at the wallet's own agent — which does not
serve `rooms/records/*`. Nothing type-checks as wrong, and the render harness
answers by task URI regardless of recipient, so tests pass.

That narrowing is deliberate: the offscreen document **mints and signs** the
envelope rather than counter-signing one composed in a page, because a wallet
that signs a document composed elsewhere attests to fields it never checked.
Widening the carrier to pass a recipient through would trade a real property for
a convenience.

So the answer taken for `rooms/keys/backfill` and `rooms/owner/register` is the
answer here: **the member's own agent makes the host call, in their name.**

---

## 2. What a read-through actually is

A member reading one record from a sealed room is four acts, and today they are
owned by three parties:

| # | Act | Who can do it |
|---|---|---|
| 1 | mint an authority presentation | the agent (`rooms/keys/present`) |
| 2 | ask the host for the record | anyone who can reach the host |
| 3 | check what came back | anyone — but only with the room's state |
| 4 | open the ciphertext | the agent, and **only** the agent |

Step 4 is the one that decides it. The epoch key never leaves the key holder, by
design; `rooms/keys/open` exists precisely so plaintext, not keys, crosses the
boundary. A console doing 2 itself would still make two more round trips to its
agent for 1 and 4, and would be the only party holding a *half-verified* record
in between.

One task, `rooms/keys/read`, does all four. Its cousin `rooms/keys/browse` does
1–3 for a listing (there is nothing to open — a listing carries no bodies), and
`rooms/keys/write` composes the existing `rooms/keys/seal` with the host call.

None of this is novel; `rooms/keys/backfill` is the template, down to the error
codes (`hostUnreachable`, `hostRefused`) and the `actsAsSubject: true` that says
what such a task really is. The machinery is built:
`operations/room_host.rs`'s `send_room_task` selects a transport from the host's
DID document, and `verify_host_reply` checks the reply's proof **and** binds the
proven signer to the host that was addressed.

---

## 3. The part that is new: step 3 needs a memory

This is the reason to write a note rather than three specs.

`dataCommitment` is a host's assertion about which records a room holds. Per
[`rooms/records/list`](https://trusttasks.org/spec/rooms/records/list/0.1), a
root read once, in isolation, proves nothing — it becomes evidence only when
compared against a copy the host did not choose. The specification offers three
such copies:

1. the root the host gave **another member**;
2. the root it gave **the same member earlier**;
3. the **witnessed anchor**.

(3) is unbuilt and blocked: it rides
[`data-rooms-epoch-anchoring.md`](data-rooms-epoch-anchoring.md)'s open question.
(1) needs members to gossip, and rooms have no gossip channel — deliberately, on
a `private` room a member list is the thing being withheld.

**(2) is available today, and it needs exactly one thing: somewhere to keep the
last root.** A console tab cannot — it is gone when the tab is. A CLI cannot. The
agent can, and already keeps per-room state (`room-group:{roomId}`).

### What it remembers, and why the pair matters

Not roots. **`(headVersion, root)` pairs.**

A bare root is not comparable to another bare root, because a room moves: every
put, curate and retraction changes the tree, so two roots differing is the most
ordinary observation there is. A host shown to have served two different roots
answers *there was a write between your reads*, and nothing contradicts it. This
is the correction made in `trust-tasks-tf#422` — an STH is a root *and* a size,
and the family had shipped only the root.

With the pair, the rule is one line:

> Two roots at the **same** `headVersion` that differ is a host caught. There is
> no write to attribute the difference to.

And the agent is the only member-side party positioned to apply it, because it is
the only one that saw both reads.

### What it does not catch

Worth stating plainly, because the mechanism is easy to oversell:

- **A consistently lying host.** One that omits a record from every read, to
  every member, and understates `recordCount` to match, is internally consistent
  and this catches nothing. What it changes is that the host is now making a
  *specific claim*, which a writer's signed put acknowledgement (vti #1334/#1335)
  contradicts directly.
- **A host that never stored the record.** The tree commits to what the host
  holds.
- **Anything at all, on the first read.** A memory of one is not a comparison.

---

## 4. Cost

| Piece | Where | Size |
|---|---|---|
| `rooms/keys/{read,browse,write}` | spec, then `vta-service/src/trust_tasks` | Three tasks on the `backfill` pattern. Six census sites each. |
| Trace verification | `vti_rooms::merkle` (built) + a wrapper | Hashing. `verify_inclusion` exists; what is missing is *reassemble the preimage from a response and check it*, which is presently inline in a test. |
| The root memory | a VTA keyspace row per room | Two integers and a digest per observation. Bounded — see §5. |
| The console panes | `manager/panes/rooms.tsx` | Record list, record view, record editor. |

No new dependency, no new cryptography, and nothing that touches how a record is
sealed.

---

## 5. What has to be decided

**One question, and it is not a small one: what does the agent do when it catches
a host?**

Three answers, and the note deliberately does not pick:

- **Refuse the read.** Honest, and it makes the detection load-bearing. It also
  means a member whose host has misbehaved once loses access to their own room
  through their own agent — including, plausibly, the records they need to prove
  what happened.
- **Return the record, flagged.** The member keeps working. A flag that appears
  in a pane and blocks nothing is a flag that gets dismissed, and the room's
  vocabulary has no word for *this host has been caught* that is stronger than a
  pill.
- **Refuse to write, serve reads.** The asymmetry has some logic — writing to a
  host you have caught equivocating is the act that compounds the damage, while
  reading is how you gather evidence — but it is a rule nobody would guess, so it
  would need to be said very loudly on screen.

A second, smaller question rides along: **how much history does the agent keep?**
Retaining every `(headVersion, root)` grows without bound. Retaining only the
latest catches a host that answers two reads inconsistently and misses one that
alternates. The obvious middle — the last N, plus the highest `headVersion` ever
seen — is probably right, and "probably" is why it is written here.

---

## 6. Recommendation

Build `rooms/keys/read` and `rooms/keys/browse` first, **with verification and
without the memory.** They unblock the console immediately, and trace
verification against the root in the same response is worth having on its own —
it is what makes a served trace mean anything at all.

Then add the memory as a second increment, once the question in §5 has an answer.
It is a strictly additive change to a task that already exists by then, and it is
the one piece here that turns a commitment from a number into a check.

`rooms/keys/write` last. It composes two things that already work and unblocks
nothing that reading does not.
