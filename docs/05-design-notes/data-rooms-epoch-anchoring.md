# Anchoring a room's renewals in its witnessed log

Status: **decided, and now buildable.** This was an open question; it was
answered on 2026-09-09 and the note is kept as the reasoning behind the answer
rather than as a request for one.

[`data-rooms.md`](data-rooms.md) §9 says a renewal writes the room's current
**MLS epoch authenticator** and **version watermark** to the room's witnessed
`did:webvh` log. It did not say *where in the log entry they go*, and there was
no obvious slot. **They go in a typed service entry — §3a.** The alternatives in
§3b and §3c are kept because a shape chosen with its rejected siblings deleted is
one nobody can argue with later.

The other question §5 raised — *what a client does with a mismatch* — is
answered too, and by the same decision that answers it for
[`data-rooms-read-through.md`](data-rooms-read-through.md): **serve reads, refuse
writes.** The two notes were asking one question in two vocabularies.

---

## 1. Why it matters — three attacks that die together

§9 is precise about what the anchor buys, and it is not integrity of the
records (they are signed and location-bound already). It is three claims a host
can otherwise make that nobody can contradict:

| Attack | What the anchor gives a member |
|---|---|
| A host says a live room lapsed, and reclaims it | The witnessed renewal exists; the host's claim is refutable |
| A host-as-Delivery-Service **forks the group**, showing different commit sequences to different members | Members compare their own epoch authenticator against the anchored one — a fork shows up as a mismatch |
| A **mirror** serves a fresh member a rolled-back room | Any client has a witnessed version floor and can tell it is being served an old room |

The middle one is the reason this is not optional decoration. MLS's own threat
model names DS-driven forking as the deployment risk, and the design's answer is
"anchor the epoch authenticator somewhere the DS does not control". Without the
anchor, the fork defence in §5.2 is a promise the code cannot keep.

**None of it works unless the anchor is witnessed**, which is the constraint
that narrows the options below: witnesses co-sign a *log entry*, so an anchor
that does not ride one is a value the host could equally have made up.

---

## 2. What a log entry actually offers

`didwebvh-rs` 0.6 (`LogEntry1_0`) is:

```rust
pub struct LogEntry1_0 {
    pub version_id: String,                       // integer-prevhash
    pub version_time: DateTime<FixedOffset>,
    pub parameters: Parameters1_0,                // closed struct
    pub state: Value,                             // the DID document
    pub proof: Vec<DataIntegrityProof>,
}
```

Which rules out most of the design space immediately:

- **`parameters` is closed.** `Parameters1_0` is a spec-defined struct
  (`updateKeys`, `nextKeyHashes`, witness config, …) with no extension member.
  Putting the anchor here means a didwebvh **specification** change, upstream,
  before a line of it can be written.
- **`versionId` / `versionTime` are computed.** Neither carries payload.
- **`proof` is the witnesses' signature over the rest.** It secures the anchor;
  it cannot be the anchor.
- **`state` is a free `serde_json::Value`** — the DID document. It is the only
  slot in the entry that will carry an ecosystem-defined value today, and
  anything in it is covered by the proof, and therefore witnessed.

So the answer is "somewhere in `state`", and the real question is **what shape**.

---

## 3. Three shapes, and what each costs

### 3a. A typed service entry — **decided**

```jsonc
"service": [
  { "id": "did:webvh:…#tsp", "type": "TSPTransport", "serviceEndpoint": "…" },
  {
    "id": "did:webvh:…#epoch-anchor",
    "type": "RoomEpochAnchor",
    "serviceEndpoint": {
      "epoch": 7,
      "epochAuthenticator": "z6Mk…",   // multibase, from RoomGroup::epoch_authenticator()
      "versionWatermark": 412
    }
  }
]
```

**For.** It is the workspace's existing extension point — every transport a VTA
advertises is a service entry matched on `type` (`TSPTransport`,
`DIDCommMessaging`, `VTARest`, `WebVHHosting`), and this reads as one more of
those. It is DID-Core-legal, so no resolver drops it. A member checking the
anchor *resolves the room DID*, which they already know how to do, rather than
fetching a log and parsing entries. And the design's own service-ordering rule
(`sort_services_canonical`) already has a place to put it.

**Against.** A `serviceEndpoint` holding structured data rather than an endpoint
is a mild abuse of the member's name — though DID Core permits a map, and the
`#tsp` entry already carries a DID rather than a URL.

### 3b. A top-level extension property on the document

```jsonc
{ "id": "did:webvh:…", "verificationMethod": [...],
  "https://openvtc.org/vocab#roomEpochAnchor": { "epoch": 7, … } }
```

**For.** Honest about not being a service. Fully JSON-LD-legal with a term
definition in the OpenVTC context, which the workspace already publishes.

**Against.** Unknown top-level properties are the members most likely to be
dropped by an intermediary or normalised away, and a reader has to know the
vocabulary URI. Nothing else in this workspace does it.

### 3c. Do not put it in the document at all — take it upstream

Ask the didwebvh working group for a general-purpose `annotations` (or similar)
member on the log entry, and anchor there.

**For.** The cleanest home: the anchor is metadata *about the entry*, not about
the DID subject, and it does not deform the document.

**Against.** It blocks on a specification change to a spec the workspace does not
own, and §9's defences stay unbuilt in the meantime. Reasonable as a *later*
migration once there is operational experience — and the shape in 3a is what
that experience would be based on.

---

## 4. The cost nobody has stated: the anchor is public

Worth surfacing before anyone chooses, because it is not in §9 and it cuts
against the tiers.

A room's DID document is **public and resolvable by anyone**. An anchor in it
publishes, to the whole world:

- **that the room is being renewed, and how often.** A high-assurance room
  anchoring per commit publishes its commit rate — which is its membership-change
  rate.
- **its version watermark**, which is a monotonic count of writes. Two
  resolutions a week apart give an observer the room's write volume.

The design already accepts that a room's *existence* and its *owner* are public
(invariant I1 — the owner is always known). Cadence and volume are new, and they
are exactly the shape of metadata the `private` tier exists to withhold from the
**host**. It would be odd to deny it to the host and publish it to everyone.

Three ways out, and the choice belongs with whoever owns the tier semantics:

1. **Accept it.** State plainly that anchoring publishes cadence, and let a room
   that cares anchor rarely (the anchoring cadence is already a room parameter
   in §9).
2. **Anchor a hash, not the values.** Publish `H(epochAuthenticator ‖ watermark ‖
   salt)` and let a member who knows the values verify the commitment. Kills the
   volume leak; keeps the cadence leak, which is inherent to writing an entry at
   all.
3. **Anchor only on `open`/`attributed`.** Simple, and wrong in the direction
   that matters: `private` is the tier with the most to fear from a forking host,
   so withholding its fork defence to protect its metadata trades a security
   property for a privacy one.

**Recommendation: 2, with the salt held by the room.** It costs one hash, keeps
the fork and rollback defences intact for every tier, and reduces the public
signal to "this room renewed at these times" — which a witnessed log leaks
anyway by having entries.

---

## 5. What else has to be decided at the same time

- **Who publishes the entry.** The room's DID controller is the owner, so the
  update is an ordinary `did:webvh` update from the owner's VTA. That is
  mechanism, not question — but it means a room whose DID is host-controlled
  (§7.1's first row) cannot anchor honestly, since the party being checked
  would be writing the check. Worth stating as a constraint on that
  configuration rather than discovering it later.
- ~~**What a client does with a mismatch.**~~ **Answered: serve reads, refuse
  writes.** An anchored authenticator that does not match the member's own is
  evidence of a fork, and evidence is not an action — so the action is stated.
  Reading is how a member gathers what they need to show what happened, and the
  records that would prove it are inside the room a refusal would lock them out
  of; writing to a host you have caught is what compounds the damage. The same
  rule governs a root that fails to reconcile
  ([`data-rooms-read-through.md`](data-rooms-read-through.md) §5), because it is
  the same question. **The refusal is the mechanism and a flag is not**: a rule
  nobody would guess needs the refused write to explain itself in the room's own
  words, or the member reads it as their agent malfunctioning and blames the
  wrong party.
- **Cadence as a room parameter.** §9 says a high-assurance room anchors per
  commit. `rooms/create/0.1` has no member for it — the same gap the hosting
  axes hit in the creation-policy work — so either it is a client-side setting
  the host never sees, or it needs an upstream schema change.

---

## 6. What this unblocks

The shape is settled, so the work is bounded and sits entirely on the owner's
side:

1. `RoomGroup::epoch_authenticator()` already returns the value (implemented).
2. On `rooms/epoch/mint`, the owner's client builds the anchor and publishes a
   webvh update through their VTA.
3. A member verifying resolves the room DID, reads the anchor, and compares.

None of it needs a host change, which is consistent with §9: the host's
contribution to lifecycle is *never deciding*, and the anchor is what makes that
checkable rather than trusted.

It also unblocks something outside §9. The **data commitment** now shipped on
both read paths offers three comparisons, and the anchor is the only one that
needs neither a gossip channel rooms deliberately do not have nor durable state
in a member's agent — so until this is built, a root is comparable only by an
agent that has read the same room before. `dataCommitment` rides the same slot
this note settles, as
[`data-rooms-verified-reads.md`](data-rooms-verified-reads.md) §3.2 anticipated;
it is one more member of the `serviceEndpoint` map above, not a second
mechanism.

---

## 7. Lineage

Written 2026-09-07, after the operator guide
([`../02-vta/data-rooms.md`](../02-vta/data-rooms.md)) had to describe witnessed
anchoring as "not implemented" without being able to say what implementing it
would mean. The two sibling gaps the guide names — read mirrors, and the
`private` tier's ZK profile — are tracked there; this one is separated out
because it is blocked on a decision rather than on effort.
