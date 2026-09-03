# Data rooms

Status: **design, revision 3.** Nothing is implemented. The upstream spec work
has not started.

A **data room** is a shared, credential-governed, end-to-end-encryptable space —
a set of records held somewhere, readable and writable by exactly the parties
its credentials admit. Rooms are built from **DTG credentials** and are not
bound to any one deployment shape: the same room works inside a community,
across communities, and with no community at all.

A room serves **two audiences at once**: the humans in it, reading and curating
it as shared information, and their AI agents, recalling from and writing to it
as shared memory. One record model, consumed two ways — never a human wiki
beside an agent store (§6.1).

The motivating case is shared agent memory. An agent's own memory stays where
it is today — private to one VTA context (`vta/memory/{put,list,delete}/0.1`,
consumed by [`vta-agent-memory`](https://github.com/OpenVTC/vta-agent-memory)) —
and a room is the surface an agent *also* recalls from, whose access control
belongs to the people in the room.

Security review: [`data-rooms-security-review-v2.md`](data-rooms-security-review-v2.md)
(current, against this revision); [v1](data-rooms-security-review-v1.md) is the
dated record of the first design and what it found. Findings cited as **R‑n**
(v2) and **F‑n** (v1).

Upstream, this note feeds three PRs: the VAC in `dtgwg-cred-spec`, a top-level
`rooms/*` task family in `trustoverip/dtgwg-trust-tasks-tf`, and one question
for the DTG working group (§4.6). §12 sequences them.

---

## 1. The four topologies, and the claim that unifies them

| | Room lives | Members come from | Governed by |
|---|---|---|---|
| **T1 Personal** | my own VTA's room host | anyone I invite | me |
| **T2 Community** | a VTC | that community (typically) | the community's `rooms.rego` |
| **T3 Cross-community** | one home host, optional read mirrors | any communities' members | the home host's policy |
| **T4 Peer** | a member's VTA's room host | VRC-connected peers | nobody — the owner |

The same person should be able to create and join rooms in all four shapes, and
the difference between them should be *where the room lives and who governs
creation* — never *what a room is*.

**The unifying claim: a room's protocol is host-neutral, because room
authorization never touches a host's ACL.** Every operation on a room is
authorized by credentials the **room itself** issued — VIC to enter, VMC to
return, VAC for what you may do (§4) — verified against the room's DID. A host
that speaks the `rooms/*` task family can therefore host *any* room without
maintaining a member list of its own, and a room can move hosts without a
single credential being reissued. The host contributes storage, availability,
and (where it is a VTC) governance over what its community's members may
create. It contributes nothing to the definition of membership.

This is why the task family is **top-level `rooms/*`**, not `vtc/rooms/*` — the
registry already has service-neutral families (`vault`, `acl`, `auth`) served
by more than one component, and this is one of them.

Two of the four topologies are nearly free once T2 exists. T3 is T2 plus
nothing: a VMC binds a member to *the room*, so members from three communities
in one room is the ordinary case, not a bridge (§7.3 adds optional mirrors).
T4 is T1 with the VRC as the door: the DTG spec is explicit that community
membership is not a precondition for a VRC, and a room between two VRC-linked
peers is a node both hold VMCs to, stood up in one action from the edge.

T1 is the one with real new work in it — a VTA-side room host (§7.2) — and the
one that changes what the product is: *my own shareable space, on
infrastructure I control, interoperable with every community I belong to.*

---

## 2. Five invariants

**I1. The room owner is always known.** At every tier, in every topology. A
room has an accountable party: the controller of its DID, the issuer of its
credentials, the recipient of lifecycle notice (§9), the party a demand
reaches. Pretending otherwise produces a system that is neither private nor
accountable, and I1 keeps turning out to be what makes an otherwise-opaque
system operable.

**I2. The host is trusted for availability and nothing else.** "Zero trust" is
never zero; it is trust minimised to a named property:

| Property | Who you must trust | Why |
|---|---|---|
| Confidentiality | nobody | content sealed to keys the host never holds (§5) |
| Content integrity | nobody | records signed, relocation and replay bound out (§6) |
| Membership integrity | nobody | credentials issued by the room DID, verified against a witnessed self-certifying log (§3.2) |
| Who counts as a member | the room's owner | they issue the credentials — I1, stated not hidden |
| **Availability, non-destruction** | **whoever hosts** | bytes live somewhere; no cryptography defends against a host that stops serving |

Everything in §9 exists to bound that last row and make host misbehaviour
**provable** rather than merely possible.

**I3. Hosting is a setting, not an exit.** Who controls the room's DID and who
stores its content are separate choices (§7.1), and the model is identical
whichever way they fall. Moving a room is re-pointing a DID document, not
migrating to a different system.

**I4. A room is a DTG node with its own identity.** It has a DID; it is
addressable, messageable, and the issuer of its own credentials (§3.2). The DTG
core credentials *"create and annotate the nodes and edges of a DTG"*, and a
room is a node like any other — which is why §4 needs almost no new vocabulary.

**I5. Room authorization never uses host ACLs.** The portability invariant, and
the one that makes §1's claim true. The moment a host's ACL participates in a
room decision, that room can no longer move and that host has become part of
the membership. Credential-gated dispatch already exists as a pattern — the
VTC's join family is holder-bound with no ACL entry — and rooms generalise it.

---

## 3. The room

| | |
|---|---|
| **Created by** | anyone the host's governance permits (§7); on your own host, you |
| **Members** | an explicit set of DIDs, never a role |
| **Owner** | one known party (I1); transferable, with a nominated successor (§10) |
| **Visibility** | fixed at creation, from the ladder in §3.1 |
| **Contents** | records (§6) |

A community-wide library is a T2 room whose membership is the roster. A
"share" from your own VTA is a T1 room with three members. One model.

**Visibility is immutable for the life of the room.** You cannot un-see
cleartext; a downgrade is meaningless and an upgrade would protect only what
came after while presenting as though it protected everything.

### 3.1 The visibility ladder

One axis: **what the host can see.** Each rung gives up exactly one thing.

| | `open` | `attributed` | `private` |
|---|---|---|---|
| Record bodies | cleartext | encrypted | encrypted |
| Titles / descriptions | cleartext | encrypted | encrypted |
| Which member is acting | visible | visible | **unlinkable proof** |
| Owner | visible | visible | visible (I1) |
| Server-side search | ✅ | ❌ | ❌ |
| Per-member access log at the host | ✅ | ✅ | ❌ |
| Per-member rate limiting | ✅ | ✅ | ❌ (§4.5) |
| Recoverable from the host's backup alone | ✅ | ❌ | ❌ (§14.1) |

`open` — cleartext, searchable, fully audited; for material where the host
reading it is not a threat and losing search is a real cost. `attributed` —
the host cannot read content and still knows who acted; the tier for anyone
under an obligation to produce per-member access logs. `private` — membership
proven by an unlinkable zero-knowledge presentation (§4.4); the host verifies
that *a* member acted.

Note the ladder measures the **host**, whoever that is. On an owner-hosted
room the owner-as-host sees everything and already knows the membership — they
issued it — so the ladder largely collapses there. Choosing between a neutral
host that cannot read and a participant host that can is a real choice with a
non-obvious answer (§7.4), and the client must not present owner-hosting as
unconditionally the more private option.

### 3.2 The room's DID

A room is an entity, not a row in someone else's table.

- **Addressable** — members reference `did:webvh:<scid>:…`, not a host-local
  id. Re-point the DID document's service endpoint and the room has moved,
  with no credential reissued (I3, I5).
- **Messageable** — the DID document advertises a transport (TSP > DIDComm >
  REST, the workspace rule), so the join flow has a real recipient, the room
  can push epoch and membership changes to members over the existing delivery
  layer, and `private` traffic can ride a mediator instead of arriving from a
  member's own IP.
- **An issuer** — every VIC, VMC, and VAC in the room is issued by the room
  DID. Ownership transfer is a controller change; every credential stays
  valid.
- **Closable** — deactivating the DID ends the room, and every credential it
  issued stops verifying with no revocation list to maintain.

**Method: `did:webvh`, witnessed.** The log is hash-chained and
self-certifying, so a host serving it cannot forge it — but a host could serve
a *stale* one, or quietly drop updates. did:webvh **witnessing** (implemented
in `didwebvh-rs`: witness thresholds, witness proofs) has independent parties
co-sign log updates, which upgrades the log from "unforgeable" to
"suppression-evident": a renewal or transfer the host pretends not to have
seen is provable against the witnesses (§9, R2‑1). Same family of mechanism as
the key-transparency systems (CONIKS lineage) now standard in messaging.
Clients verify the log; they never trust the host that served it.

`did:peer` was considered and rejected: it encodes its keys in the identifier,
so the controller can never change and transfer would mean reissuing every
credential — the mass reissue this design exists to avoid.

**Where the room's signing key lives follows from who controls the DID.** A
host that holds the room's key can mint itself a VMC and join the room,
legitimately and undetectably. On `private` — and in every owner-controlled
configuration (§7.1) — the room's key custody is the owner's VTA, and transfer
moves authority by webvh pre-rotation (`vta-keys::derive_pre_rotation_keys`):
the outgoing owner publishes a witnessed log entry rotating to a key the
incoming owner already holds. No key ever ships.

**A room is not a small community.** It has an identity, members, and issued
credentials; it has no trust registry, no personhood governance, no public
presence, no recognition graph, and no policy engine of its own. Scope
discipline, written down because this is where it would erode.

---

## 4. Credentials: the DTG applied to a room

The flow is the community's flow, one level down — **VIC → present → VMC (+
VAC)** — with the room DID in the issuer's chair.

| Job | Credential | Status |
|---|---|---|
| Enter the first time | **VIC** issued by the room DID | existing type; a new variant by issuer/subject rules, exactly how the spec already distinguishes its VTC and VTN variants |
| Re-enter after joining | **VMC** pair, member ↔ room | existing type |
| What you may do | **VAC** | the one new type (§4.2) |
| In-room endorsements | VEC | existing; available, not required |
| Attesting formation | VWC | existing; available, not required |

### 4.1 Joining is consent

Without an invitation step, the owner seals a room key to your VTA and you are
simply *in*, having agreed to nothing — holding keys to material you may not
want, on `private` with nobody outside the room able to tell you are there.
The VIC makes joining a two-party act. Consent is given once; epoch changes
(§5) renew membership for members who already accepted rather than
re-inviting them.

The VIC and VMC do not collapse into one credential: a VIC is single-use and
consumed, and it names its subject, so presenting it per access would both
contradict its semantics and disclose the member.

Where the VIC travels differs by tier: on `open`/`attributed` it may ride the
host's invitation machinery (the VTC's `INVITATIONS` / `CONSUMED_INVITATIONS`
already do replay protection); on `private` it is DIDComm-only, because a
server-side invitation store would hand the host the membership at invite
time. There the owner tracks consumption — they issue, and know who they
invited — and admission control is the room's signature, not the invitation.

### 4.2 The VAC: authority, attenuable

Membership and authority are different claims and stay in different
credentials. The VMC says *you are in this room*; the VAC says *what you may
do* — `read`, `write`, `curate`, `admin`. Changing someone's access reissues
one small credential and leaves the membership edge alone.

Two design requirements on the VAC, both learned from the capability-token
literature ([UCAN](https://github.com/ucan-wg/spec),
[Biscuit](https://www.biscuitsec.org/)) rather than invented here:

- **Attenuable.** A holder can derive a narrower grant from their own —
  fewer verbs, shorter expiry, a named audience — without the issuer. The
  case that forces this is the agent: a member's VTA holds the member's VAC,
  and the member's *agent* should run on an attenuated read-only,
  hours-scoped derivative, not on the member's full authority. This is the
  room-world form of the same least-privilege argument `vta-agent-memory`
  already makes.
- **Audience-bound.** An attenuated VAC names what may wield it, so a leaked
  agent capability is not a leaked member capability.

**The latent conflation this fixes.** The VTC expresses community role grants
as a VEC with `endorsement = { type: "CommunityRole", … }`. An endorsement
asserts something *about* someone; a role grant confers authority. That is
precisely the *delegation is not authority* line the VAC name was reserved
for, so rooms introduce the VAC properly and open the path to migrating the
community case onto it later — a reason to design it well rather than
minimally.

### 4.3 The VMC and VAC must be provably about the same subject (R2‑2)

On `private`, a member presents both under zero knowledge. Without a binding,
credentials pool: one member's VMC plus another member's `write` VAC presents
as a single member with write access. The presentation must therefore carry a
**same-subject linking proof** — equality of the hidden subject across the two
credentials — which BBS+ supports and the `rooms/*` presentation schema must
require, not merely permit. This is a spec-level requirement; discovered in
implementation it would be a silent authorization bypass.

**Which subject.** Implementation settled a detail the paragraph above hides:
the VMC binds to the chain's **root**, not its leaf. The first version compared
the leaf and it refused every agent — correctly, by its own rule, because *an
agent is not a member of anything*. Its human is. The chain's root is the grant
the room made, so its subject is the member whose standing the whole chain
descends from; `verify_chain` has already established that each link's issuer is
its parent's subject, so nothing below the root can escape it. Comparing the
root admits the agent and still refuses the pooling attack: a chain rooted at
Bob cannot be presented with Alice's membership, whoever holds the leaf.

### 4.3a A presentation is bound to its presenter, not bearer

A presentation names *what may be done*, never *who is doing it* — so an unbound
one is a bearer token, and anyone who observes one inherits everything it
confers. Every room operation therefore also carries the DID that signed the
request, established by the request document's own `eddsa-jcs-2022` proof, and
the chain's leaf must grant to that party.

Worth stating explicitly because the reference implementation does **not** do it
for you: `dtg_credentials::authority::verify_chain` takes a `presenter`, but
uses it only for the `audience` check on links that name one. Binding the leaf
is the verifier's job, and a verifier that assumed otherwise would authorize
every captured presentation. Rooms check it twice — once in the credential
verifier and once in `authorize` — so the property does not depend on every
future verifier implementation remembering it.

### 4.4 Presenting membership

- `open` / `attributed` — standard W3C VC presentation; the subject is
  disclosed, which is what those tiers are for.
- `private` — a zero-knowledge presentation: *holder possesses a valid VMC
  (and VAC, same subject) from room R at epoch ≥ N*. Unlinkable across
  presentations. This is the DTG spec's own construction — the shape of its
  Community-Anchored ZKP with the room DID in the anchor position — and the
  spec says ZKP presentation SHOULD be the default, so `attributed` is the
  tier that opts *out* of the default.

The workspace can already verify these: `affinidi-bbs` (BLS12-381, IETF BBS)
is a dependency and `vtc-service` carries a BBS+ verifier behind its `bbs`
feature. Proofs are milliseconds — no circuits, no trusted setup.

**Reads present too.** A read authorized by a host session would hand the host
`(member, room, time)` on every access and reconstruct the membership from a
week of logs — v1's worst finding (F1). Reads carry the same presentation
writes do, and on `private` require no host session at all.

**Prior art this stands on:** the
[Signal Private Group System](https://eprint.iacr.org/2019/1416) (CCS 2020) is
the same architecture — a server holds encrypted group state, and members
authenticate with anonymous credentials proving only *membership*, so the
server enforces a group it cannot read. Signal uses keyed-verification
credentials (KVACs), which are cheaper but verifiable only by the issuing
server; rooms use BBS+ VCs, which any verifier — a mirror, a second host, a
peer — can check. That difference is what makes the host-neutral claim in §1
possible, and it is the deliberate trade.

### 4.5 What anonymity costs, still

BBS+ gives no nullifier, so `private` has no anonymous per-member rate limit:
one member can burn a room's quota and the owner cannot tell who (F11).
Room-level caps for v1; `attributed` for anyone who needs per-member limits; a
[rate-limiting-nullifier](https://rate-limiting-nullifier.github.io/rln-docs/)
scheme later if `private` sees abuse in practice — it buys anonymous
per-member limits and *slashing* (an over-limit member de-anonymises
themselves), and costs the circuit machinery everything else here avoids.

### 4.6 The one question for the DTG working group

A VMC attests membership *"in a VTC or VTN"*. If those name **graph-node
kinds**, a room is already a node of the kind VMC serves and the spec needs
nothing new for it. If they name **deployed services**, the spec needs a word
for this. The question gates the VIC/VMC reuse (not the VAC, which is new
regardless) and should be put to the WG now, in parallel with everything else
— it is a conversation, not a PR.

---

## 5. Keys: MLS is the group layer

Revision 2 hand-rolled the group key machinery: a room key per epoch, HPKE
fan-out to each member on every change, owner-only epoch minting, a mandatory
maximum epoch lifetime. Every one of those is a re-derivation of something
[MLS (RFC 9420)](https://www.rfc-editor.org/info/rfc9420/) standardises, and
the parts MLS adds are the parts a reference design should not be missing.
**Rooms adopt MLS as the group-key layer.**

### 5.1 The mapping

MLS's architecture splits an **Authentication Service** (who is this leaf?)
from a **Delivery Service** (who stores and orders the group's messages,
trusted for availability only). That is *exactly* this design's shape already:

| MLS concept | Rooms |
|---|---|
| Authentication Service | **the DTG**: leaf credentials are the room VMC |
| Delivery Service | **the room host** — VTC or VTA room host, trusted per I2 |
| Group | the room |
| Epoch | the epoch this note already has (§5.3 of rev 2) |
| Commit (add/remove/update) | membership change — **committed only by the owner**, an application policy MLS supports and [MIMI's room policy](https://datatracker.ietf.org/doc/draft-ietf-mimi-room-policy/) draft models the same way |
| Welcome | the invitation payload, carried inside the DIDComm VIC flow (§4.1) |
| Exporter secret | **the room storage key**: content keys derive from the epoch's exporter, the pattern [draft-sullivan-mls-attachments](https://www.ietf.org/archive/id/draft-sullivan-mls-attachments-01.html) uses for encrypted attachments, following SFrame ([RFC 9605](https://www.rfc-editor.org/info/rfc9605)) |

One leaf per member, and the leaf is the member's **VTA** — devices and agents
hang off it through the oracle model (§5.3), which sidesteps MLS's
multi-device complexity entirely.

### 5.2 What MLS buys over the hand-rolled layer

- **Post-compromise security.** A compromised member key heals at the next
  commit. The HPKE fan-out model had none: a stolen member key read every
  future epoch until someone noticed.
- **O(log n) membership change.** Fan-out is O(n) per change — fine at five
  members, wrong for a roster-sized T2 library room.
- **A standard, not a bespoke protocol.** Interop with where messaging is
  going ([MIMI](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/)
  builds interoperable rooms on MLS+HTTPS;
  [Matrix is trialling MLS](https://github.com/matrix-org/matrix-spec-proposals/blob/travis/msc/mls/00-core/proposals/4244-rfc9420-mls-for-matrix.md)),
  and audited Rust implementations exist
  ([OpenMLS](https://github.com/openmls/openmls),
  [mls-rs](https://lib.rs/crates/mls-rs)).

Honest costs, stated: MLS is a serious dependency with a complex state
machine; commits require a single sequencer (the home host is the DS, which
our single-primary model provides for free — §7.3); and the DS can attempt to
**fork the group** by showing different commit sequences to different members
— a known MLS deployment risk, addressed by anchoring epoch authenticators in
the room's witnessed DID log (R2‑3, §9). On `private`, commits travel as MLS
PrivateMessage so the host sees ciphertext and an epoch counter, not the tree.

The v1/v2 security findings the hand-rolled layer needed patches for — F5
(epoch authority), F6 (key rotation on removal), F7 (bounded epochs) — are
MLS-native: committer policy, remove-then-commit, and epoch lifetimes
respectively.

### 5.3 Custody: the VTA opens, proves, and never releases

Unchanged from rev 2 and load-bearing: the member's MLS leaf state, room
credentials, and derived content keys live in the member's **VTA**, which acts
as a **decryption and proving oracle** — the agent sends ciphertext and gets
plaintext, asks for a presentation and gets a proof. Nothing key-shaped
crosses to the agent. This is the VTA's defining property (*private key
material never leaves the VTA's process*) extended to room material, it makes
agent revocation meaningful, and with §4.2's attenuated VACs the agent holds
narrow, expiring authority rather than the member's own.

### 5.4 Recovery: a quorum re-admits; total loss is total

A member who loses their VTA lost their leaf. Recovery is **k-of-n
re-admission**: any k members attest the returning party's identity and the
owner (or the quorum, §9) commits an add for their new leaf. Not secret
sharing — every member already holds the group state, and what needs
distributing is the *authority to re-admit*, not shards of a key. Identity
assurance in that attestation is human judgement, the same problem §10.5 DID
rotation has, and should reuse whatever answer it gets (open, §14.2).

If every member's VTA is gone, the room is gone; the host holds ciphertext
and cannot help. Stated at creation, not in a footnote.

---

## 6. Records

Addressed by `(roomId, key)`. Host-neutral by construction: nothing in a
record names its host.

| Member | `open` | `attributed` / `private` |
|---|---|---|
| `key` | cleartext | cleartext, **opaque** — a descriptive key defeats the encryption beside it; structured naming lives inside the sealed body |
| `title`, `description`, `body`, `tags`, `author` | cleartext | one sealed blob (splitting leaks shape through ciphertext lengths) |
| `status` | `active` \| `deprecated` \| `retracted` | same, cleartext |
| `version` | server-assigned, monotonic per room | same |
| `epoch` | n/a | cleartext, AEAD-bound |
| `createdAt` / `updatedAt` | cleartext | cleartext |

The rules carried from the app-state store, adopted not re-derived:
`expectedVersion` preconditions with the conflict carrying the winner;
`expectedVersion: 0` create-only; cursor pagination (`vti_common::pagination`)
and `sinceVersion` watermarks; tombstones on delete so sync converges; a
stated per-record size cap. The version counter is per **room** — one
comparable number is what `sinceVersion` needs.

**Every write is bound to its location.** The write's presentation commits to
`(roomId, key, version, epoch, H(ciphertext))`, and the host rejects a
`(roomId, key, version)` it already holds — the cut-and-paste class
`vti_common::store::encryption` fixed once with location-bound AAD, repeated
rather than rediscovered. In-room attribution is a signature by the member's
DID over the plaintext, inside the sealed body; on `private` it is the only
attribution that exists.

`list` returns metadata, `get` returns bodies. On encrypted tiers the client
fetches and decrypts metadata to rank — affordable because rooms are small,
and one concrete reason `open` (server-side search) continues to exist.

### 6.1 Written for humans, recalled by agents

The dual audience is a constraint on the **record**, not a pair of features:

- **Bodies are human-readable text** (markdown), never model-optimised blobs.
  An agent that saves something only a model can parse has failed half the
  room. The discipline is *write for the human; recall for the agent* — the
  same rule `vta-agent-memory` already applies to personal memory.
- **The `description` serves both**: it is the agent's ranking surface and the
  human's one-line scan surface, which keeps one field honest for two readers.
- **Authorship names the acting party.** The in-body signature says which
  member — and, when the writer was an agent acting under an attenuated,
  audience-bound VAC (§4.2), *that it was the agent*, and which one. A human
  reading a room can tell colleague-written from colleague's-agent-written,
  and an agent recalling can weight accordingly. Attenuation is what makes
  this checkable rather than self-declared.
- **Curation verbs are for people.** `curate` (pin, deprecate, retract) is
  human judgement over shared knowledge; agents read `status` and must treat
  `deprecated` as demoted in recall. Nothing stops a community granting
  `curate` to an agent; the default posture should not.
- **Untrusted in the human direction too (R2‑16).** Bodies are member-authored
  markdown rendered in trusted-feeling surfaces, which makes a room a
  phishing channel as well as an injection channel. Human surfaces render
  inert — no script, no active content, sandboxed links — with the same
  discipline the agent surface applies to instructions.

**Deliberately not adopted: CRDTs.** The local-first literature would make
records mergeable and hosts optional even for writes. The cost is semantic
merge complexity for content whose merge semantics nobody has asked for, and
a much harder confidentiality story. Single write-primary with version
preconditions is the boring, sufficient answer; revisit only if concurrent
offline editing becomes a real requirement.

---

## 7. Hosting

### 7.1 Two separable choices

Who controls the room's **DID** (trust: keys, credentials, membership) and who
stores the **content** (availability) are independent:

| DID | Content | |
|---|---|---|
| host | host | Convenient; the host could forge the log — witnessing (§3.2) makes that evident, custody (§3.2) makes self-admission impossible only if the key is elsewhere |
| **owner** | **host** | **The default worth recommending**: the host provably cannot join or fork the room, and durability, availability, quota and backup still ride the host |
| owner | owner | Full independence — T1 and T4 |
| host | owner | no meaningful use |

### 7.2 The room host is a component, not a place in the VTA

T1 says "a room on my VTA". It must **not** mean new credential-gated network
surface inside `vta-service` — the process guarding the master seed is the
wrong place to terminate presentations from arbitrary DIDs (R2‑4). The room
host is a **separate small service, provisioned by the VTA** exactly as
mediators and webvh hosts are: a `room-host` DID template, the
provision-integration flow, custody staying with the VTA. The VTC, which
already terminates holder-bound tasks from strangers, implements the same
`rooms/*` family in-process.

So "my VTA hosts my room" means: my VTA minted and controls the room host's
identity, my VTA holds every key, and a small hardened service holds the
records. That is the stack's own integration pattern, applied.

### 7.3 Mirrors, and why not replication

A room has **one write-primary** (the DS — MLS needs a sequencer anyway) named
in the room DID's service endpoints, and optionally **read mirrors**: other
hosts (say, a second community's VTC in T3) holding ciphertext copies fed by
`sinceVersion` pulls. Records are signed and location-bound, so a mirror
cannot tamper; it can only be stale or silent, and a member's watermark
detects regression (a fresh member should bootstrap from the primary, R2‑5).

Multi-primary replication is a **non-goal**, learned from a decade of Matrix:
replicated multi-writer room state needs state-resolution machinery whose
failure modes ([state resets](https://matrix.org/blog/2025/08/project-hydra-improving-state-res/))
took years to shake out. Notably Matrix itself has arrived where this design
starts — [room IDs are now the hash of the create event](https://github.com/matrix-org/matrix-spec-proposals/blob/matthew/msc4291/proposals/4291-room-ids-as-hashes.md)
(self-certifying room identity, their Room v12), which is the property the
room DID's SCID gives here from day one.

### 7.4 Governance is the host's, and its limits are stated

A VTC governs what **its members may create on it** via `rooms.rego`
(visibility tiers permitted, hosting axes, member count, cross-community —
the input contract carries `didControlledBy` and `contentStoredAt`).
Default-ship: `open` + `attributed` permitted, `private` denied until enabled;
both hosting axes permitted, because **deny is only honest where the host
actually decides** — a community can refuse to *host* an owner-controlled
room; it cannot prevent a member standing one up elsewhere (T1/T4), any more
than it can stop them joining a foreign `private` room it cannot see. A
community may forbid either **as governance** — membership consequences, not
a technical boundary — and should say so in policy rather than have it
discovered.

A personal room host (T1) is governed by its owner. That sentence is the
entire policy model for T1, and it is enough.

---

## 8. Audit

`open`/`attributed`: the host's audit machinery, with `room.*` actions; reads
are the interesting event on shared material. The read log is itself a privacy
artifact — actor-hashed but operator-reversible on a VTC — so room read events
carry their own retention policy and an actorless recording option. On
`private` the host records that *a member* acted; who-did-what exists only
inside the room (in-body signatures), reconstructed client-side as a
members-only view covering writes — reads leave no trace anyone can
reconstruct, including the owner. Agents read constantly, so read-volume
anomaly detection is a dead end on every tier.

---

## 9. Lifecycle: renewed, not reaped — and provably so

No host can promise to hold every room forever, and on an encrypted room the
host is the worst-placed party to judge value: it cannot read the content,
and inactivity is not worthlessness. So the host never decides.

**The clock is the epoch.** MLS epochs already have a maximum lifetime (§5);
renewal is a commit. **Live → lapsed** (epoch expired: read-only, nothing
destroyed) **→ dormant** (owner notified — I1 — and a notice posted into the
room) **→ reclaimable** (after the retention period stated at creation).
Reversible by a single renewal until the last step; exportable before
reclamation, so the members' choice is *renew or take it with you*.

**Renewals are anchored in the witnessed DID log (R2‑1, R2‑3, R2‑5).** Each
renewal (at minimum, one per maximum epoch lifetime) writes an entry carrying
the current **MLS epoch authenticator** and the room's current **version
watermark** to the room's witnessed webvh log. Three attacks die together: a
host cannot claim a live room lapsed (the witnessed renewal exists); a
host-as-DS cannot fork the group unnoticed between anchors (members compare
their epoch authenticator against the anchored one — anchoring cadence is a
room parameter, and a high-assurance room anchors per commit); and a mirror
cannot serve a fresh member a rolled-back room (any client has a witnessed
version floor). What survives is a host that deletes anyway — I2's
irreducible row — now as **provable misbehaviour** rather than a deniable
shrug.

Owner absence must not kill a live room: the nominated successor claims
(§10), or the k-of-n quorum renews. Where the host stores nothing (owner-hosted
content), lifecycle is wholly the owner's.

**Read activity does not extend the clock, and the implementation departs from
an earlier draft of this paragraph on purpose.** "A room actively read and
never written is an archive" is right about what deserves protecting and wrong
about how. A *host* counting reads to decide a sealed room's lifecycle would
make that lifecycle depend on the one signal the host can see — which is
exactly the correlation the tiers exist to deny, and it would give a
`private` room an access-frequency profile its members were promised it would
not have. Liveness is expressed by renewing, and a room being read is a room
whose members are in a position to renew it. The archive case is served by
`retentionDays`, which is the member's own statement of how long the room
matters, made at creation where it belongs.

---

## 10. Ownership and succession

The owner: controller of the room DID, issuer of every credential, sole MLS
committer, accountable party, lifecycle addressee (I1's several jobs).

- **Transfer** re-points the DID controller via witnessed pre-rotation
  (§3.2); every credential stays valid.
- **Succession**: a nominated successor *claims* — never auto-promotes into —
  ownership when the owner's reachability or membership lapses. Load-bearing
  for liveness, not just administration: no owner, no commits.
- **Orphaned**: no successor → the room freezes (key-holders read, nobody
  writes) and the host may reclaim per §9's stated schedule.
- **Departed members' contributions stay, attributed.** Membership gates
  reaching a room, not the room's possession of what was contributed.
- **Deletion** in-room stays tombstone-then-purge, two verbs, per §6.

---

## 11. Prior art, taken and declined

What a reference design owes its readers: where each piece stands, and what
was deliberately not used.

| Source | Taken | Declined |
|---|---|---|
| [MLS, RFC 9420](https://www.rfc-editor.org/info/rfc9420/) | the whole group-key layer: epochs, PCS, committer policy, exporter-derived storage keys | — |
| [MIMI protocol](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/) + [room policy](https://datatracker.ietf.org/doc/draft-ietf-mimi-room-policy/) | hub-as-DS shape; room policy as a first-class, declared document | its identifier and discovery layer — rooms have DIDs |
| [Signal Private Group System](https://eprint.iacr.org/2019/1416) | the architecture of `private`: server enforces a membership it cannot read | KVACs — keyed verification binds verification to one server; BBS+ VCs keep hosts, mirrors and peers all able to verify |
| Matrix ([Room v12 / MSC4291](https://github.com/matrix-org/matrix-spec-proposals/blob/matthew/msc4291/proposals/4291-room-ids-as-hashes.md), [Project Hydra](https://matrix.org/blog/2025/08/project-hydra-improving-state-res/)) | self-certifying room identity (they converged on it; DID+SCID starts there) | multi-primary replication and state resolution — single write-primary + mirrors instead |
| did:webvh witnessing (`didwebvh-rs`), key-transparency lineage | suppression-evident logs; renewal + epoch anchoring (§9) | — |
| [UCAN](https://github.com/ucan-wg/spec) / [Biscuit](https://www.biscuitsec.org/) | VAC attenuation + audience binding (§4.2) | token-chain formats — the VAC is a VC, at home in the DTG |
| [RLN](https://rate-limiting-nullifier.github.io/rln-docs/) | named as the future answer to anonymous rate limiting | for v1 — circuits |
| Local-first / CRDTs | the warning about host-optional writes | mergeable records (§6) |
| BBS+ / DTG ZKP presentations | already the stack's own | — |

---

## 12. Sequence

0. **DTG WG question** (§4.6) — start now; it gates VIC/VMC reuse.
1. **VAC** in `dtgwg-cred-spec` (DCO, personal fork). The only new credential.
2. **`rooms/*` top-level family** in `dtgwg-trust-tasks-tf`: room lifecycle,
   records, epoch/commit relay, presentation envelope **including the
   same-subject binding (§4.3)** — wire-shape commitments are cheap here and
   version-folder-expensive later. Full recipe, one PR, lockstep bump.
3. **`open` on the VTC**, end to end: keyspaces (in `ALL` + `BACKED_UP`),
   storage, credential-gated dispatch, `rooms.rego`, audit, conformance
   census. No crypto; settles the room model.
4. **`attributed`**: room DIDs (witnessed), MLS via OpenMLS (host as DS),
   VTA custody + oracle, DIDComm VIC/Welcome flow, exporter-derived storage
   keys.
5. **`private`**: ZK presentation against the existing `bbs` verifier, with
   §4.3's linking proof. A presentation-mode change if 1–4 are right.
6. **`room-host`** integration (template + small service) → T1 and T4.
7. **Mirrors** (T3) — `sinceVersion` pulls, read-only.
8. **Client** (`vta-agent-memory`): recall union with provenance, attenuated
   agent VACs, explicit contribution, tier legibility.

Orthogonal and first: **F8** — fence recalled shared content as data, never
instructions, in the agent-memory skill; it needs nothing above and hardens
today's personal memory. And the `MemoryRead`/`MemoryWrite` capability split
on `vta/memory` (the published spec already assumes it; the implementation
gates only on context).

### 12.1 In flight

| Step | Where | State |
|---|---|---|
| This design set | `verifiable-trust-infrastructure` #1233 | open |
| **F8** — untrusted-content fencing | `vta-agent-memory` #13 | open |
| `MemoryRead`/`MemoryWrite` | `verifiable-trust-infrastructure` #1234 | open |
| **VAC** (§1 of the sequence) | `trustoverip/dtgwg-cred-spec` #29 | open |
| `Capability` enum reconciliation | `dtgwg-trust-tasks-tf` | in progress |

Two things the implementation work surfaced that the note had not:

- **The registry's `Capability` enum was already behind the workspace**, missing
  `sign-trust-task` and `credential-write` before this design added two more.
  The reconciliation PR carries all four rather than widening the gap.
- **The two published `device/_shared` versions disagree on casing** — 0.1 is
  kebab-case (which `vti_common::acl::Capability` implements) and 0.2 is
  camelCase. Additive values go into both in their own convention; the casing
  divergence is a separate question for whoever owns device bindings.

---

## 13. The client

Two clients per room, one record model (§6.1).

**The agent surface** (`vta-agent-memory`): one recall union over personal
memory plus every room the member's VTA holds a leaf in; provenance on every
shared result (room + author + human-or-agent, from the in-body signature);
**shared content fenced as untrusted input** — a room is a writable channel
into every member's agent context, and marking content as communal does not
stop a model obeying it (F8); contribution and cross-room movement as explicit
user acts; agents run on attenuated, expiring VACs (§4.2), never the member's
own.

**The human surface**: the room as a readable, curatable space — a member-facing
room view in the VTC's web surface, the mobile agent
(`vta-mobile-agent-ios`), and Cierge as consumers. Same records, same
credentials, same oracle path through the member's VTA. Humans get search
(`open`) or client-side filtered browse (encrypted tiers), the members-only
audit view (§8), and the curation verbs. The tier and topology stay legible at
the point of use for both audiences — a human should know the operator can
read an `open` room the same way an agent's recall marks one.

---

## 14. Open

1. **Recovery vs. total loss** — the k-of-n quorum answers member loss;
   nothing answers all-members loss, by design. Communities choosing
   `attributed`/`private` accept it at creation.
2. **Quorum identity assurance** (§5.4) — reuse §10.5 DID-rotation's answer
   when it has one; also: may a quorum renew against a *reachable but
   unwilling* owner? (R2‑6 says no — renewal-by-quorum is for absence, and
   the spec must say how absence is established.)
3. **Anonymous rate limiting** (§4.5) — RLN if `private` sees abuse.
4. **The DTG node-kind question** (§4.6).
5. **Curation semantics** — pinning, review, supersession: from use.
6. **Names** — `rooms/*` is the family slug; the product name is a separate
   decision under the `Agent[Capability]` house style.

---

## 15. Lineage

Three revisions, each ended by a correct objection. **Rev 1** was a
role-governed community library on the VTC; it died because "operator must
not read" is a requirement cryptography has to meet, not policy. **Rev 2**
rebuilt it as encrypted rooms with a shared-secret signature and
blind-by-omission membership; its review (v1, seventeen findings) killed the
shared secret, and *use the DTG credentials properly* replaced the bespoke
membership machinery with VIC/VMC/VAC issued by a room that is itself a DTG
node. **Rev 3** (this document) made the room host-neutral across four
topologies, adopted MLS as the group layer, witnessed the room's log, and
bound the credentials to each other. The constants across all three: the
owner is always known, and the host is trusted for availability alone.
