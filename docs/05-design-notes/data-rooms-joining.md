# Joining a room when you have no inbox

Status: **proposal for review, not a plan**, and deliberately not a spec.
[`data-rooms-demo-site.md`](data-rooms-demo-site.md) §4.3 says the pull-shaped
join "should go upstream as a Trust Task family **once the demo has shown its
shape**", and the demo is unbuilt. This note works out the shape far enough to
be argued with, and names the one thing the demo is genuinely needed to settle.

---

## 1. The gap

Twenty-two room tasks and **not one is a join request**. A VTC has
`join-requests/*`; a room has nothing.

That is not an oversight so much as a consequence. Admission is **push-shaped**:
the owner calls [`rooms/keys/key-package`](https://trusttasks.org/spec/rooms/keys/key-package/0.1)
*on the member's VTA*, then `keys/welcome`, then issues the membership and
authority credentials. Every step assumes the joiner is an agent with an address
the owner can reach.

A browser tab is not. Neither is a phone app, a CI job, or anything else that
holds a channel to its own agent and to nothing else. For those, admission has
to invert: **the applicant offers, the owner accepts.**

## 2. The room is already addressable, and the template says so

This is the part that makes the design small, and it was already decided.

A room's DID document names a mediator, and `vta-sdk/templates/room.json` says
why in as many words:

> `MEDIATOR_DID` makes the room addressable, which is what lets an invitation, **a
> join**, or an epoch notice reach it.

So there is no new address to invent and no discovery problem to solve. An
applicant holds `{roomDid, host}` — the same pair `pnm-cli` takes as `--room` and
`--host` — resolves the room DID, finds its mediator, and sends there. The
owner, as the room's DID controller, is the party that collects from it.

**A join therefore goes to the room, not to the host and not to the owner's own
DID.** The owner's DID is knowable (invariant I1 makes the owner visible at every
tier) but it is the wrong address: it points at a *person's* agent rather than at
the room, so a room whose ownership transfers would leave applicants writing to
whoever used to hold it.

## 3. Why it must not go through the host

Routing a join through the host is the obvious shortcut — the applicant is
already talking to one — and it is wrong on the tier that matters.

A `private` room withholds its membership from its host by construction. A join
request that passes through the host tells it **exactly who wants in**, which is
a strictly better signal than the membership it was denied: applicants are
self-selected and the timing is unambiguous. A host that logged nothing else
could reconstruct the room's growth from join traffic alone.

So the host is off this path for the same reason it is off the Welcome path
([`data-rooms.md`](data-rooms.md) §5.6), and for once the alternative costs
nothing: the room is already addressable.

## 4. What a request carries

Sketch, not a schema:

- **A key package.** The MLS credential the owner needs to add a member, minted
  by the applicant. This is what makes the request an *offer* rather than a
  petition — the owner can act on it without a second round trip.
- **The identifier the applicant wants to be known by.** A `did:key` a browser
  minted, most of the time. On an `attributed` room this becomes the `author` on
  everything they write; on `private` it does not leave the sealed body.
- **Whatever evidence the room asks for**, which is §5 and is the open question.

And the response carries **nothing but an acknowledgement**. The admission
itself arrives later, as the existing `keys/welcome` + `owner/issue-membership`
+ `owner/issue-authority` sequence, because that sequence already works and a
join that tried to return credentials synchronously would make the owner decide
inside a request timeout.

## 5. The open question: what makes an applicant admissible

Everything above is mechanism. **This is policy, and the design has no answer in
it.**

- An **`open`** room may want anyone with a DID, or anyone holding a credential
  from some issuer, or anyone at all subject to a rate limit.
- An **`attributed`** room needs the applicant's identifier to mean something,
  since it will be on their records.
- A **`private`** room admitting strangers is close to a contradiction: the tier
  exists to withhold who is in it, and a join channel anyone may use is a way to
  find out by trying.

None of that is answerable from first principles, and inventing an
`admissionPolicy` enum now would be inventing three answers to a question nobody
has asked in anger. **This is what the demo is for.** It will run an `open` room
with auto-admission and a real audience, and the first thing it learns is what
gets abused.

Two things worth deciding *with* that evidence rather than before it:

1. **Whether the room or the owner decides.** A rule the room publishes is one an
   applicant can read before applying, and one a host could enforce on the
   room's behalf. A rule the owner applies privately discloses less and cannot
   be checked. The first sounds better and may leak the membership criteria of a
   room that would rather not state them.
2. **Where a refusal goes.** Silence is the safest answer for a `private` room
   and the worst for an `open` one, where an applicant with no reply cannot tell
   refusal from a lost message.

## 6. Cost, once §5 is answered

| Piece | Where | Size |
|---|---|---|
| `rooms/join/request/0.1` | spec | S — one payload, one acknowledgement |
| The room's inbox drain | owner's VTA | M — the owner already holds the room's keys; what is new is polling a mediator on the room's behalf |
| Admission decision | owner's surface | M, and entirely §5 |
| Applicant side | wasm member half | S — it already mints key packages |

Nothing here needs a host change, a new credential, or a change to how a record
is sealed.

## 7. Recommendation

**Do not write the spec yet.** The mechanism is settled enough that writing it
would be easy, and that is exactly the trap: the part that would need changing
afterwards is §5, and §5 is the part a spec would freeze.

Build the demo's `POST /join` as the demo note already plans, with auto-admission
on an `open` room. Then upstream `rooms/join/request/0.1` from what it turned
out to need — which is what §4.3 asked for, and what this note exists to make
concrete rather than to pre-empt.
