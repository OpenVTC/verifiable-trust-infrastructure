# Community data rooms

Status: **design.** Nothing here is implemented. The upstream spec work has not
started.

Member-created, end-to-end encrypted **data rooms** on the VTC: any member can
stand up a room with any set of other members, its contents readable only by
them, with the community setting — by policy — what kinds of room may exist at
all.

The motivating case is shared agent memory. Today an agent's memory is private
to one VTA context (`vta/memory/{put,list,delete}/0.1`, served by
`vta-service/src/trust_tasks/memory.rs`, consumed by
[`vta-agent-memory`](https://github.com/OpenVTC/vta-agent-memory)). That stays
the default and this note does not change it. What it adds is a shared surface
an agent can also recall from, whose access control belongs to the people in the
room rather than to the service holding it.

This note exists for the same reason `appstate-store.md` did: the dispatcher
refuses to serve a Trust Task URI the published registry has no schema for, so
the first deliverable is a schema in another repository and this note is its
input. §12 sets out the sequence.

---

## 1. Why not the memory family

The closest existing thing is `vta/memory`, and reusing it would be a mistake
for reasons that mirror — and in two cases exceed — the ones that kept
application state out of it (`appstate-store.md` §1).

**Single-writer assumptions are baked in.** `MemoryItem` is `{key, value}`. No
version, no timestamp, no author, nothing to hang a precondition on. Two agents
writing the same key overwrite each other and neither can detect it afterwards.
Tolerable when the only writer is your own agent; intolerable the moment a room
is shared.

**`list` returns everything.** `memory/list/0.1` returns *every entry in the
context, in ascending key order* — no prefix, no cursor, no search.

**And the settling argument, which is the same one as last time pointed the
other way:** *"forget everything" must stay a safe thing for a user to ask their
agent.* If room content lived in the agent's own memory family, either the
user's "forget everything" destroys other people's shared work, or it silently
does not do what it says. Both are wrong. Rooms have to be addressed
differently so that clearing personal memory cannot reach them.

Two further properties have no analogue in the memory family at all:
**attribution** (who contributed this) and **encryption the service cannot
undo** (§5).

Different store, different family: `vtc/rooms/*`.

---

## 2. The primitive is a room, not a shelf

An earlier draft of this note proposed a community-wide **library** of shelves,
role-governed by the VTC. That model is not gone — it survives as the `open`
tier in §3 — but it is no longer the primitive, because it answered the wrong
question. The thing people want is not a curated community archive. It is *"a
private space for me and these three others, that the platform cannot read."*

So: **a room is the unit.** A community-wide library is a room whose membership
happens to be the whole roster. One model, one key mechanism, one thing to
explain.

| | |
|---|---|
| **Created by** | Any member, subject to policy (§4) |
| **Members** | An explicit set of DIDs, not a role |
| **Owner** | One visible, accountable member; transferable, with a nominated successor (§9) |
| **Visibility** | Fixed at creation, from the ladder in §3, permitted by policy |
| **Contents** | Records, shaped as in §6 |

**Visibility is immutable for the life of the room.** You cannot un-see
cleartext, so a downgrade is meaningless; and an upgrade would only protect
records written after it, while presenting as though it protected all of them.
To change the visibility of some material, make a new room and move it
deliberately.

### 2.1 Where a two-person room comes from

The VTC already stores **VRCs** — member-issued Verifiable Relationship
Credentials, one row per edge, indexed by DID for both issuer and subject
(`vtc-service/src/relationships/`). A pairwise room is the storage projection of
a relationship the community already models. Creating a room between two members
who hold a VRC edge should be one action from that edge, not a fresh
introduction ceremony.

---

## 3. The visibility ladder

This is the optionality the design turns on. Three tiers along **one axis: how
much the VTC can see.** Each step up gives up exactly one capability, and it is
worth being explicit about which, because a community choosing a tier is
choosing what it loses.

| | `open` | `attributed` | `blind` |
|---|---|---|---|
| Record bodies | cleartext | **encrypted** | **encrypted** |
| Titles / descriptions | cleartext | encrypted | encrypted |
| Room membership | visible | visible | **blinded** |
| Writer identity | visible | visible | **blinded** |
| Owner | visible | visible | visible |
| Server-side search + filtering | ✅ | ❌ | ❌ |
| Server-side membership enforcement | ✅ | ✅ | ❌ — key possession is the gate |
| Per-member access audit at the VTC | ✅ | ✅ | ❌ — §8 |
| Per-member rate limiting | ✅ | ✅ | ❌ |
| Recoverable from a VTC backup alone | ✅ | ❌ | ❌ — §13.1 |

**`open`** is the role-governed shelf from the earlier draft: cleartext at rest,
gated by `VtcRole` plus policy, fully searchable and fully audited. Right for
community reference material — conventions, decisions, onboarding — where the
operator reading it is not a threat and losing search is a real cost.

**`attributed`** encrypts content but keeps the VTC's knowledge of who is in the
room and who wrote what. The operator cannot read the material and can still
enforce membership, attribute abuse, and rate-limit. This is the tier most
communities should default to, and the one that gives up least for what it buys.

**`blind`** additionally hides the membership and the writer. The VTC holds a
room id, an owner, an epoch, a quota, and ciphertext. Everything else it knows
about the room is inference from timing and size. §7 covers the mechanics this
forces.

### 3.1 What a store-level encryption key does not buy

`vti_common::store::encryption` already provides AES-256-GCM at rest, AAD-bound
to `(keyspace, key)`, and works without a TEE given an explicit
`storage_encryption_key`. It is worth saying plainly why that does **not**
satisfy `attributed` or `blind`: the VTC process must hold that key to serve
reads, and the operator controls the process. Store-level encryption defends
against a stolen disk or a leaked backup. It does not defend against the
operator, and nothing deployed on hardware the operator controls can — §3-K
makes TEE a permanent non-goal for the VTC. Only keys the VTC never holds do
that, which is why §5 puts them in member VTAs.

---

## 4. Community policy: `rooms.rego`

*Optionality is the requirement.* A community must be able to say "no rooms at
all", "rooms, but never blind ones", or "blind rooms, but only for these
roles" — and the VTC already has the machinery: embedded `regorus`, explicit
activation, no hot-reload (§3-D, §7.2).

`rooms` becomes a new row in §7.1's required-policy table.

**Input contract** (§7.3 gains the matching entry):

```jsonc
{
  "actor":  { "did": "...", "role": "member", "foreign": false },
  "action": "create" | "invite" | "write" | "transfer",
  "room":   { "visibility": "blind", "memberCount": 4, "ownerDid": "...",
              "crossCommunity": false }
}
```

**Default-ship policy**: members may create `open` and `attributed` rooms;
`blind` is **denied** until a community turns it on. Not because blind rooms are
wrong — the whole of §7 exists to make them work — but because a community that
has not thought about §8 (no per-member access audit) and §13.1 (a VTC backup
does not recover the room) should meet those properties by opting in, not by
discovering them. Every other default in this stack that could surprise an
operator is deny-first; this matches.

`Custom` roles receive **no implicit grants**, per §5.3. The standard matrix
must not be bridged onto them by similarity.

### 4.1 A policy change is not retroactive

If a community later forbids a tier, the VTC can refuse new rooms at that tier
and can refuse further **writes** to existing ones. It cannot make existing
content readable — it never could read it. State this in the policy
documentation, because an operator who activates a restrictive policy expecting
it to reach backwards has misunderstood what they bought.

---

## 5. Keys

**Custody is the member's own VTA.** The room key is HPKE-sealed to each
member's key-agreement key and held in their VTA — the custody plane, per §3-A.
The agent asks its VTA to unwrap per session. Consequences worth the choice:
the key survives a laptop, it is covered by the VTA's encrypted backups, and
revoking an *agent's* ACL entry does not hand that agent a room key it can keep.

`vta_sdk::sealed_transfer` is the existing primitive — X25519 + HPKE, with a
versioned `SealedPayloadV1` enum (`vta-sdk/src/sealed_transfer/bundle.rs:33`).
A `RoomKey` variant is an additive change to that enum, not a new mechanism.

**Invitations travel over DIDComm, not through the VTC.** The invite carries the
sealed room key straight to the invitee's VTA. This is what makes `blind`
possible at all: the VTC never handles the invitation, so it never learns who
was invited.

### 5.1 Epochs, and what removal actually achieves

Removal mints **epoch N+1**, sealed to the remaining members only. Records carry
the epoch they were written under; the VTC stores the epoch number as cleartext
metadata (it must, to serve the right ciphertext) and nothing else about it.

The removed member keeps whatever they could already read. That is not a
weakness being tolerated, it is the truth: they held the plaintext. Re-encrypting
history would deny them only the records they were entitled to read and had not
got round to fetching, at the cost of a full room rewrite on every removal.
**Forward-only, and say so in the UI** — a member who thinks removal retracts
history will be wrong in a way that matters.

---

## 6. Records

Addressed by `(roomId, key)`.

| Member | `open` | `attributed` / `blind` |
|---|---|---|
| `key` | cleartext | cleartext (opaque; see below) |
| `title` | cleartext | inside the sealed body |
| `description` | cleartext | inside the sealed body |
| `body` | cleartext | inside the sealed body |
| `author` | cleartext | inside the sealed body (`blind`); cleartext (`attributed`) |
| `tags` | cleartext | inside the sealed body |
| `status` | `active` \| `deprecated` \| `retracted` | same, cleartext |
| `version` | server-assigned, monotonic per room | same |
| `epoch` | n/a | cleartext |
| `createdAt` / `updatedAt` | cleartext | cleartext |

On the encrypted tiers, **one sealed blob holds title, description, author,
tags and body together.** Splitting them would let the VTC learn the shape of
the material from ciphertext lengths for no benefit, since the client decrypts
the whole record either way.

**Record keys on encrypted tiers must be opaque** — a random id, not a
descriptive `<type>/<slug>`. The `vta-agent-memory` convention of structured
keys exists so a type filter can run before decoding; on an encrypted tier that
filter would run at the VTC, which is exactly what the tier forbids. Keys that
say `decision/acquire-northwind` defeat the encryption they sit beside. The
client keeps its structured naming *inside* the sealed body.

### 6.1 The properties `vta/memory` does not have

| Property | Behaviour |
|---|---|
| `expectedVersion` on `put` | Optional precondition; on mismatch a typed conflict **carrying the current version and record** |
| `expectedVersion: 0` | Create-only — fail if the key exists |
| Cursor pagination on `list` | Opaque, signed cursors |
| `sinceVersion` on `list` | Only what changed since a watermark |
| Tombstones on `delete` | Versioned, retained (§10) |
| Stated size limit | Per-record cap, and a loud error at it |

The per-room counter, the conflict-carries-the-current-value rule, and
tombstones-make-sync-converge are settled arguments from `appstate-store.md` §2,
adopted rather than re-derived. In particular the counter is per **room**, not
per record, because `sinceVersion` needs one comparable number and per-record
counters are not comparable to each other. That was learned by building the
app-state store and should not be learned twice.

### 6.2 `list` returns metadata, `get` returns bodies

On `open`, this is the quality argument from the `vta-agent-memory` README — *a
memory service that pastes every body into the context window has made the
session worse* — and ranking happens client-side over descriptions.

On the encrypted tiers it is also a bandwidth argument, and it is weaker: since
descriptions are sealed, the client must fetch and decrypt every record's
metadata blob to rank. **This is affordable precisely because rooms are small.**
It would not be affordable for a community-wide archive, which is one concrete
reason `open` continues to exist rather than being the tier nobody picks.

---

## 7. Blind-tier mechanics

Everything in this section applies only to `blind`. It is the tier that costs
real machinery, which is why §4 makes a community ask for it.

### 7.1 Two signatures, doing two different jobs

**Outer, at the VTC.** Room creation registers a room **verification public
key**; the private half travels with the room key. Every write is signed with
it. The VTC verifies that signature and learns exactly one fact: *the writer
holds this room's secret.* It can reject junk from anyone who merely guessed a
room id, without learning which member wrote.

**Inner, inside the ciphertext.** The record body carries a second signature
over the plaintext by the member's own DID. Room members verify it on decrypt
and get real attribution. The VTC cannot see it.

That split is what makes "the VTC cannot see the membership" compatible with
"the VTC will not host junk", and it needs no primitive the stack lacks.

### 7.2 Room ids must be unguessable

The VTC's only gate on a blind room read is a valid session plus knowledge of
the room id. High-entropy random ids, and never derived from anything about the
room or its members.

### 7.3 Discovery: the member's VTA is the index

There is no per-member index at the VTC, because there is nothing it could key
one on. A member's VTA holds the room keys it has been sealed, and that set
*is* the answer to "which rooms am I in".

The alternative — members registering blinded per-room tags the VTC can look up
— was considered and rejected for v1. It buys recovery when a member's local
state is gone, and it costs a set of tags correlatable across a querying
session, which is a hole in exactly the property the tier exists to provide.
Recovery is real, though, and §13.1 is where it is unresolved.

---

## 8. Audit

**On `open` and `attributed`**, the VTC's existing audit envelope applies
unchanged — HMAC-hashed actors, signed checkpoints. `room.create`,
`room.write`, `room.read`, `room.epoch`, `room.transfer` join the action
vocabulary. Note that auditing **reads** matters here in a way it does not for a
private store: reads of shared material are the interesting event.

**On `blind`**, the VTC can only record that *someone holding the room key*
acted. That is a genuine loss and must be documented rather than glossed: an
operator can never answer "who read this document".

Attribution moves inside the room. The client reconstructs a per-member history
from the inner signatures (§7.1) and presents a **members-only audit view**.
Two honest limits on that view:

- It covers **writes only**. A read leaves no in-content trace, so no
  reconstruction can produce one. "Who has read this" is not answerable on a
  blind room by anyone, including its owner.
- It is only as complete as the records still present. A retracted record's
  inner signature goes with it.

---

## 9. Ownership and succession

Every room has exactly one **visible owner** — the accountable party for quota,
abuse handling, and any request the operator is obliged to act on. Visible at
every tier, including `blind`; it is the one thing blinding does not cover, by
design.

- **Transferable.** The owner may hand ownership to another room member. The
  VTC records the new owner; the transfer is audited.
- **Nominated successor.** The owner may name a successor who can *claim*
  ownership if the owner's community membership lapses. Claiming is an explicit
  act by the successor, not an automatic promotion — an automatic one would move
  an accountable role onto someone who may not know they hold it.
- **No successor, owner gone.** The room freezes: existing key-holders read, no
  writes, and the operator may reclaim storage after a stated retention period.
  Freezing rather than deleting, because the VTC cannot tell whether the content
  still matters to the people who can read it.

An owner is not privileged *inside* the room. On `blind` it could not be — the
VTC cannot distinguish the owner's writes from anyone else's once they are past
the outer signature.

---

## 10. Deletion, departure, retention

**Delete writes a tombstone**, not an erasure: the body goes, the key, version,
epoch and `retractedAt` remain. Incremental sync needs the tombstone to converge
(§6.1), and on `open` the audit chain needs the record to have demonstrably
existed. A second, owner-only **hard purge** removes the tombstone and is itself
audited. Two verbs because they are two different acts; collapsing them makes
the common one too powerful or the rare one impossible.

**A departed member's contributions stay, attributed.** Membership gates
*reaching* a room, not the room's continued possession of what was contributed
to it. Authorship stays honest against the DID that wrote it. The alternative —
retract on departure — makes a mass departure a mass loss of shared work.

---

## 11. What to reuse rather than invent

| Need | Existing asset |
|---|---|
| Sealing room keys to members | `vta_sdk::sealed_transfer` (X25519 + HPKE), plus a `RoomKey` payload variant |
| Delivering invitations | DIDComm, via the member's mediator |
| Cursor pagination | `vti_common::pagination` — opaque base64url cursors, HMAC-SHA256-signed so one maintainer's cursor cannot be replayed against another |
| Policy | Embedded `regorus`, `POST /v1/policies/{id}/activate`, no file-watching |
| Audit | The VTC envelope, HMAC-hashed actors, signed checkpoints |
| Pairwise room provenance | The VRC edge already in `relationships:` (§2.1) |
| Cross-community rooms | §8.4 recognition, unchanged: pass `foreign` + the recognised role into `rooms.rego` |
| Keyspace hygiene | `ROOMS`, `ROOM_RECORDS` in `vtc-service/src/store/keyspaces.rs`, registered in `ALL` **and** `BACKED_UP` — the two must partition `ALL` exactly, and `backup_partition_is_total` enforces it |
| Conformance | Every new URI in `DISPATCHED_URIS` (`vtc-service/src/trust_tasks/mod.rs:162`) with a published schema. Do not shortcut through an unspecced-URI allowlist |

---

## 12. Sequence

The upstream dependency is load-bearing and sets the order.

1. **Author the schemas upstream** in `trustoverip/dtgwg-trust-tasks-tf`:
   `spec/vtc/rooms/{create,get,list,transfer,close}/0.1`,
   `spec/vtc/rooms/records/{put,get,list,delete,purge}/0.1`,
   `spec/vtc/rooms/keys/{epoch,seal}/0.1`, plus `_shared` types carrying the
   visibility enum and the sealed-record envelope. Roughly twelve specs. This
   note is the input.
   The whole recipe lands in one PR or the merge publishes nothing: schemas →
   `npm run validate` → `cargo run -p trust-tasks-codegen && cargo fmt --all` →
   `npm run build-ts-bindings` → `npm run check-bindings` → lockstep version
   bump of `trust-tasks-rs` **and** `trust-tasks-ts` with CHANGELOG entries.
   Declare no JSON Schema `default` on an optional member — a declared default
   is materialised by the bindings and breaks round-trip idempotence.
2. **Bump `trust-tasks-rs`** in this workspace so `schema_index::schema_for`
   resolves the new URIs. Until this lands, step 3 cannot pass its own tests.
3. **`open` tier end to end** in `vtc-service` — keyspaces, storage,
   operations, handlers, routes, audit, conformance witnesses. No crypto. This
   proves the room model, the versioning, the pagination and the policy hook
   against the simplest tier.
4. **`rooms.rego`** — default-ship policy, §7.1 table row, §7.3 input contract.
5. **`attributed`** — the `RoomKey` sealed-transfer variant, VTA-side key
   custody verbs, DIDComm invitation, client-side seal/open, epochs.
6. **`blind`** — room verification key, outer signature verification, opaque
   ids, VTA-side room index, members-only audit view.
7. **`vtc-client` + `vta-agent-memory`** — see §13.

Steps 1–2 are in another repository and on another team's cadence. The
implementation is weeks, not the days the app-state store took, because §5–§8
are real cryptographic machinery rather than a keyspace. Budget a correction
round: `appstate-store.md` records that implementing found two spec defects and
one design error in that note, and calls "specify, then implement, then correct
the spec" the honest shape of it.

**Do the tiers in order.** `open` first is not a stepping stone that gets thrown
away — it is a tier communities will choose — and building it first means the
room model is settled before the crypto lands on top of it.

### 12.1 One orthogonal fix, blocked by none of this

**There is no read-only grant on memory today.** The gate in
`vta-service/src/trust_tasks/memory.rs` is
`auth.require_context(&req.context_id)` and nothing else: a DID that can read a
context can write and delete it. The `--read-only` flag in
`vta-mcp/src/guard.rs` is an operator-supplied glob filter on the MCP bridge —
client-side, and not encountered by a caller talking to the VTA directly.

The published spec already assumes the split exists:
`specs/vta/memory/delete/0.1/spec.md` warns that *"a VTA whose write capability
is granted more freely than its read capability has, through this task, granted
a narrow read as well."* There is no read capability and no write capability;
there is a context. Nor does the ACL supply one — the act axis is
`(role, allowed_contexts)` decoded to a three-valued `ActScope`
(`acl-scope-semantics.md`), a *where* with no *what*, and
`vti_common::acl::Capability` (`vti-common/src/acl/mod.rs:123`) has no memory
variants.

Add `MemoryRead` / `MemoryWrite`, wire them through
`derived_capabilities_for_role`, check them alongside `require_context`. Legacy
rows with an empty `capabilities` set already fall back to the derived mapping,
so existing grants keep working. Small, closes a gap the published spec assumes
is closed, and proves the read-only primitive on the single-writer store first.

---

## 13. The client is where the value lands

Most of what a user experiences is in `vta-agent-memory`, and the `open`-tier
version of it can be built against a stub before any crypto exists.

**One recall surface, several backends.** Recall unions personal memories with
the rooms the member's VTA holds keys for, ranks them together over
descriptions, returns the winners.

**Provenance is not optional.** Every room result must be marked as shared, in
the text the model sees, with its room and its author. An agent that cannot
distinguish "you told me this" from "someone in your data room wrote this down"
will assert the second with the confidence of the first, and the user has no way
to tell. This is the single most important client-side requirement in the note.

**Contribution is explicit.** Promoting a personal memory into a room is a
deliberate act with a visible diff, never a background sync. Personal memory
contains things that must not leave the machine, and no store can tell which.

**Read-only is the default posture.** Most members recall from a room far more
than they write to it.

**The tier must be legible in the UI.** A member writing into an `open` room
should be able to tell, without checking, that the operator can read it.

---

## 14. Still open

1. **Key escrow, and what a VTC backup is worth.** This is the largest
   unresolved risk in the note. A VTC backup of an encrypted room restores
   ciphertext. If every member loses their VTA, the room is gone permanently —
   the operator holds the bytes and cannot help. Options are all
   unattractive: community key escrow (which weakens the tier), a
   member-held recovery share, or an accepted and clearly-stated loss. It has
   to be answered before `attributed` ships, not before `open` does.
2. **Room-list recovery on `blind`** (§7.3). If a member's VTA is restored from
   a backup that predates a room, they have no way to learn the room exists.
   Related to (1) and probably answered with it.
3. **Quota and abuse handling on `blind`.** The operator has a visible owner and
   per-room byte counts, and no per-member rate limit. Whether that is enough
   is an operational question this note cannot settle.
4. **Curation semantics.** `deprecated` versus `retracted` is asserted, not
   argued. Whether rooms also need pinning, review, or supersession edges
   (`this memory replaces that one`) probably arrives from use.
5. **The family name.** `vtc/rooms` is a spec slug and reads as what it is. The
   product name is a separate decision under the Affinidi `Agent[Capability]`
   house style, and should not be settled by whatever the schema directory ends
   up called.
