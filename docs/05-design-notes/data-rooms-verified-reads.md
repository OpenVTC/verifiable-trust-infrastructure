# Verified reads: making a withheld record detectable

Status: **proposal for review, not a plan.** [`data-rooms.md`](data-rooms.md)
§14.7 sizes this and does not schedule it. This note works it out far enough to
be argued with, and names the two things that have to be decided before any of
it could be built.

It shares an unanswered question with
[`data-rooms-epoch-anchoring.md`](data-rooms-epoch-anchoring.md) — *where in a
witnessed log entry does an anchored value go* — and that is not a coincidence.
The commitment proposed here is a **third value in an anchor that is already
specified and not yet built**, which is most of why this is smaller than it
first appears: it does not need its own mechanism, it needs one more field in a
mechanism §9 already owes.

---

## 1. The gap, stated precisely

A room's records are signed by their writer and bound to the room. A host
therefore cannot forge a record, alter one, or move one between rooms — those
attacks are already dead.

**Silence is free.** `rooms/records/list` returns a set, and nothing in the
response says the set is complete. A host serving nine records from a room that
holds ten is indistinguishable, to every member, from a room that holds nine.

What the anchor §9 specifies would catch is a **rolled-back room**: the version
watermark bounds the top of the version space, so a host cannot serve an old
room as a current one. It would not catch a **withheld record**, because a
watermark says how high the versions go and nothing about which of them exist. A
host that omits version 47 while honestly reporting a watermark of 50 is not
contradicted by anything a member holds.

(That anchor is specified and unbuilt — `RoomGroup::epoch_authenticator` exists
and nothing writes it to a log yet — which is why the note beside this one is
about where it would go.)

That asymmetry is worth naming plainly: the room's integrity story is strong
about *what a record says* and silent about *which records there are*.

### Why this matters more here than in an ordinary store

A room is read by **agents**, and an agent recalls from it to answer. A record a
host quietly withholds does not produce an error a person would investigate; it
produces an answer that is confidently incomplete. The failure mode of a missing
record is a wrong answer, not a visible gap — which is the shape of failure this
whole design has tried to avoid everywhere else.

---

## 2. What Encrypted Spaces does, and which half is cheap

[Encrypted Spaces](https://encryptedspaces.org/) §3.3 builds three things over a
Merkle key-value store, and they are separable:

| | What it is | Cost |
|---|---|---|
| **Trace** | The subtree needed to replay a sequence of reads and writes and bind them to a data commitment. A single read is an ordinary inclusion proof. | Hashing. Logarithmic in tree size. |
| **Update proof** | A change plus its trace, replayed by the client: carries the commitment from `DC` to `DC'`. | Hashing, by the client, per change. |
| **Fast-forward proof** | A zkVM proof that a *batch* of changes carried `DC` to `DC'`, so a client that was offline need not replay. | A GPU per batch. |

**Only the third needs a zkVM**, and the third exists to solve a problem rooms
solve differently. In ES a client's trusted commitment comes from having
followed every update since the last one it verified; a client that was offline
for a month either replays a month or verifies a fast-forward proof.

A room has an anchor ES does not: a **witnessed log**. A returning member does
not need to replay anything, because the room's own log carries a commitment
that witnesses co-signed. That is the substitution this note proposes, and it is
what takes the zkVM out of the design.

---

## 3. The proposal

### 3.1 A Merkle key-value store under the records prefix

`vti_rooms::storage` already keys records as `rec:<roomId>:<key>` and scans them
by prefix, so they are an ordered key-value store in everything but name. The
leaf commits to the record's *metadata and ciphertext digest* — **not its
plaintext**, which the host does not have on a sealed tier and must not need.

An ordered tree is what makes a **range** provable, and range proofs are where
completeness comes from: an inclusion proof says "this record is here", and only
a range proof says "and there is nothing between these two keys".

### 3.2 The commitment rides the anchor

§9 specifies that a renewal writes the MLS epoch authenticator and the room's
version watermark to its witnessed log. This adds a third value to that same
entry, the **data commitment** — the tree's root at that moment.

The consequence is the whole point: **any member can obtain, from a source the
host does not control, a root that the host is bound to.** Witnesses co-signed
it; a host serving a listing that does not reconcile with it is caught by
arithmetic rather than by suspicion.

This inherits the open question from the anchoring note rather than adding a new
one. Whatever slot the epoch authenticator lands in, the commitment lands beside
it.

### 3.3 Traces on reads

`rooms/records/get` and `rooms/records/list` responses carry a trace rooted at a
named commitment. A client checks the trace, checks the root against the anchor
it holds, and thereby checks that what it received is exactly what the tree held.

Adding query shapes needs no new proof machinery — ES's observation that "any
operation expressible as reads and writes against the ordered key-value store is
traced the same way" holds here too.

---

## 4. What this buys, and what it does not

**It buys:** a host cannot omit, from a listing, a record that was in the tree at
the last anchored commitment, without any member who checks being able to tell.
Nor can it show two members different record sets as of that anchor, because the
anchor is witnessed and singular.

**It does not buy**, and the design must say so out loud:

- **Completeness is only as fresh as the anchor.** Records written since the last
  renewal are outside the committed set. The property is "complete as of epoch
  N", and a room that renews rarely has a wide window. That is a real limitation
  and it is bounded and legible, which is better than the current position of no
  property at all.
- **It does not stop omission at commit time.** The root is computed over what
  the host holds. A host that never stored a record, or dropped it before the
  anchor, commits to a tree without it and the commitment is internally
  consistent. What the commitment changes is that the omission becomes
  **attributable**: it is now a specific, witnessed claim about the room's
  contents that a writer can contradict.
- **It says nothing about deletion a host admits to.** Retention and curation are
  separate questions with their own answers.

### 4.1 The prerequisite: a writer holds no receipt today

The bullet above only works if a writer can contradict the commitment, and right
now they cannot. `PutRecordResponse` is `{key, version, epoch?}` — **unsigned**.
A member who wrote a record and later finds it absent from a witnessed
commitment has the host's word that the write happened, and the host's word is
the thing in dispute.

So this design has a cheap prerequisite that is worth doing on its own merits:
**sign the put acknowledgement**. A writer then holds a host-signed statement
that record `K` reached version `V`, which a commitment omitting `K` directly
contradicts. Without it, verified reads detect an inconsistency and cannot
attribute it.

This is the part of the proposal most likely to be worth building first, because
it is small, it stands alone, and every later layer depends on it.

---

## 5. Cost

| Piece | Where | Size |
|---|---|---|
| Ordered Merkle KV over `rec:<roomId>:` | `vti_rooms::storage` | The real work. Tree maintenance on every put and curate. |
| `dataCommitment` in the anchor | wherever the epoch authenticator lands | One field — but it inherits the anchor, which is itself unbuilt |
| Traces on `get` / `list` responses | `vti-rooms` wire + both hosts | Additive response members |
| Signed put acknowledgement | `vti-rooms` wire + both hosts | Small, and independently useful |
| Client verification | `vti-rooms` (shared) + the agent | Hashing; no new dependency |

No zkVM, no new cryptographic assumption, no change to the credential model, and
nothing that touches how a record is sealed.

---

## 6. What has to be decided first

1. **Where the anchored values go in a log entry.** Already open in
   [`data-rooms-epoch-anchoring.md`](data-rooms-epoch-anchoring.md); this adds a
   value to the same slot rather than a second question.
2. **Whether "complete as of the last renewal" is the property we want to
   claim.** It is weaker than continuous completeness and much stronger than
   nothing. If it is not enough, the next step is update proofs broadcast on
   write (ES's online path) — still no zkVM, but it puts a verification cost on
   every member for every write, and that is a different trade to make
   deliberately.
3. **Whether a host is willing to be bound this way at all.** A commitment is a
   claim a host can be caught breaking. That is the point, and it is also a
   thing an operator is entitled to weigh before adopting.

---

## 7. Recommendation

Take §4.1 now, independently: **sign the put acknowledgement**. It is small, it
is useful without any of the rest — a writer holding a receipt is better than a
writer holding nothing — and it is load-bearing for everything above.

Treat the Merkle store as a genuine piece of work to schedule rather than slip
in, and settle question 2 before starting it, because the answer decides whether
the tree is maintained per-write or per-renewal.
