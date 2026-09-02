# Security review v2 — data rooms

Reviewed: `data-rooms.md` **revision 3** (four topologies, DTG credentials,
MLS group layer, witnessed room DIDs, dual human/agent audience), 2026-09-01.
Design stage; every finding is cheap now and wire-breaking later.

[Review v1](data-rooms-security-review-v1.md) examined revision 2 and stands
as a dated record; its seventeen findings are not restated. Five were
dissolved by the move to DTG credentials, and the ones that survive are
carried here by reference (F8, F11, F15, F16). This review examines what
revision 3 **added**: host-neutrality across four topologies, the MLS
delivery-service role, witnesses, mirrors, attenuated agent capabilities, the
recovery/renewal quorum, and the human surface.

Findings **R2‑1 … R2‑16**, ranked. Where the design note already adopted a
fix, the finding records what the fix must hold; "adopted" does not mean
"done" — nothing is implemented.

## Threat model

The parties, and what each is trusted for:

| Party | Trusted for | Adversarial capability examined |
|---|---|---|
| Host (VTC / room-host / mirror) | availability only (I2) | read what it stores; forge, reorder, suppress, delete; equivocate between members |
| Room owner | membership correctness (I1) | over-admit, refuse removal, vanish, collude with host |
| Member | in-room conduct | collude, pool credentials, spam, inject content at agents, leak |
| Removed / foreign member | nothing | retain, replay, re-enter |
| Member's agent | acting within its VAC | compromised or manipulated by room content |
| Mediator / transport | routing | correlate who-talks-to-whom (F4 boundary, I2) |
| **Witness** (new) | co-signing log honesty | collude with host; go offline |
| **Quorum** (new) | re-admission and renewal judgement | admit an impostor; act against the owner |

The central assumption is unchanged from v1 and still the one most often
wrong: **the trust boundary is per operator, not per service.** A witness run
by the host's operator is not a witness.

---

## High

### R2‑1. The host can walk a live room to reclamation — mitigated to *provable*, not prevented

The lifecycle (§9) lets storage be reclaimed after a renewal drought. The
host serves epoch state and relays renewals, so an unmitigated host could
suppress renewals or misreport the epoch and walk a live, valued room from
lapsed to reclaimable — destruction wearing a lifecycle policy's clothes.

**Adopted fix:** renewals are entries in the room's **witnessed** webvh log.
A host claiming "no renewal" against a witnessed renewal is exhibiting
provable misbehaviour, and members hold the log independently.

**What the fix must hold:** the retention clock runs from the *witnessed log*,
never from host-local state; reclamation requires the host to cite the last
anchored renewal; and a host that deletes anyway remains within I2's
irreducible availability trust — the guarantee is evidence, not prevention.
Say that in operator-facing documentation, because "witnessed" will be
misread as "cannot be lost".

### R2‑2. Unlinked VMC + VAC presentations pool into forged authority

On `private`, membership (VMC) and authority (VAC) are presented under zero
knowledge. Without a binding, two colluding members combine one's VMC with
the other's `write` VAC and present as one member with write access — a
silent authorization bypass no log would ever show.

**Adopted fix (§4.3):** the presentation schema **requires** a same-subject
linking proof (equality of the hidden subject across both credentials; BBS+
supports this). The requirement must be in the `rooms/*` presentation schema
from its first version — retrofitting it is a breaking change to every
verifier — and conformance tests must reject an unlinked presentation, not
merely accept a linked one.

### R2‑3. The host-as-DS can fork the group

MLS needs the delivery service to sequence commits, and the home host is the
DS. A malicious host can **equivocate**: show member A one commit sequence
and member B another, splitting the room into two groups that each believe
they are the room — the classic MLS deployment risk, and on `private` the
members cannot compare notes through the host by construction.

**Adopted fix (§9):** the current MLS **epoch authenticator is anchored in
the witnessed DID log** at every renewal. Members compare their epoch
authenticator against the anchor; a forked member fails the comparison.

**Residual, stated:** detection latency equals anchoring cadence. Between
anchors, a fork is live. If a room's threat model can't accept that window,
the owner anchors more often — the cadence should be a room parameter, not a
constant — and high-assurance rooms can anchor per-commit.

### R2‑4. Terminating stranger presentations on the custody root

T1 puts a room host "on my VTA". Implemented literally — new
credential-gated network surface inside `vta-service` — that parks a parser
for adversarial input from arbitrary DIDs on the same process that guards
the BIP-39 master seed. Wrong blast radius, regardless of parser quality.

**Adopted fix (§7.2):** the room host is a **separate provisioned
integration** (a `room-host` DID template through provision-integration),
holding records and terminating presentations, with nothing key-shaped in it
— keys stay in the VTA behind the oracle. The VTC implements the family
in-process because it already terminates holder-bound tasks from strangers;
the VTA never does.

**What the fix must hold:** the room-host must be *unable* to reach VTA
surfaces beyond the oracle verbs it needs — scope its ACL entry to exactly
those. A room-host with a general-purpose VTA credential recreates the blast
radius one hop away.

### R2‑5. A mirror can serve a fresh member a rolled-back room

Mirrors (§7.3) hold signed, location-bound ciphertext, so they cannot tamper
— but they can be **stale or selectively silent**. An existing member's
`sinceVersion` watermark detects regression. A **fresh member has no
watermark**: a malicious mirror (or a compelled one) can present a
plausible, internally consistent, *old* room — records retracted since, a
member list epoch since rotated.

**Fix, partially adopted:** fresh members bootstrap from the write-primary,
never a mirror. **Recommendation beyond the note:** the anchored renewal
entry (R2‑1) should also carry the room's current **version watermark**, so
that *any* client — fresh included — has a witnessed floor: a mirror serving
versions below the anchored floor is exhibiting rollback. This makes the
anchor serve three duties (liveness, fork detection, rollback floor) for one
log entry.

---

## Medium

### R2‑6. The quorum can act against the owner, not just for them

Rev 3 lets the k-of-n quorum **renew** a room when the owner is absent
(liveness) and **re-admit** members who lost their VTA (recovery). Neither
defines *absence*. A quorum that renews against a reachable-but-unwilling
owner has overridden the room's sole authority; a quorum that re-admits
someone the owner removed has reversed a removal. The spec must define how
absence is established (e.g., signed non-response to a witnessed challenge
over a stated period), and must scope quorum re-admission to *members in
good standing who lost key material* — never to parties the owner removed.
Carried as open in the note (§14.2); it is a finding here because the
ambiguity is exploitable, not merely untidy.

### R2‑7. Witnesses are now trust infrastructure, and nobody has said who they are

R2‑1/R2‑3/R2‑5 all lean on witnesses. Witnesses that are the host's operator
under another name restore every attack they were meant to make evident;
witnesses that are offline block legitimate log updates (a liveness failure
the host will be blamed for). The design needs a **witness selection
policy**: chosen by the owner; independent of the host operator (per the
per-operator boundary above); for T3 rooms, naturally one per represented
community; and a stated threshold that tolerates witness loss. `didwebvh-rs`
already implements thresholds — the policy, not the mechanism, is the gap.

### R2‑8. Attenuated VACs must narrow monotonically and verifiably

§4.2's agent capabilities are the right shape and import the classic
capability-chain pitfalls: an attenuation that *extends* (more verbs, longer
expiry than its parent), a chain the verifier doesn't walk to the root, a
stolen agent credential replayed past its audience. The `rooms/*`
presentation schema must require the full chain, verify monotonic narrowing
at every link, enforce audience binding, and cap chain depth. UCAN's
published mistakes are the checklist; do not rediscover them.

### R2‑9. KeyPackage delivery must not become a membership oracle

MLS adds members via KeyPackages. If invitees publish KeyPackages to — or
owners fetch them from — a **host directory**, the host observes who is
being invited to what, un-blinding `private` at the door. KeyPackages and
Welcomes must travel inside the DIDComm invitation flow (§4.1), end to end,
with the host seeing only the resulting opaque commit. This is a wire-flow
requirement for step 4 of the sequence, cheap now.

### R2‑10. Auto-renewal turns the liveness signal into an uptime signal

Owners will automate renewal the moment it is possible — a VTA policy that
renews on schedule — at which point "renewed" means "the owner's VTA is
plugged in", not "humans still value this room", and §9's design premise
quietly dies. The renewal act should carry a freshness of *intent* the spec
can at least distinguish: an automated renewal marked as such, so a host's
retention policy (and a community's `rooms.rego`) can treat N consecutive
automated renewals as the dormancy signal they actually are. Social
problem, partial technical mitigation; flagged so the erosion is a choice.

### R2‑11. Owner-hosted rooms concentrate seizure value on one person

In T1/T4 the owner's VTA controls the room DID, holds the owner's leaf, and
provisions the room-host storing the records. Compromise or seizure of that
one machine yields keys *and* ciphertext *and* identity — strictly worse
concentration than the split-custody T2 arrangement (owner keys, host
bytes). This is the honest cost of independence and belongs beside §7.4's
"owner-hosted is not automatically more private": it is not automatically
more *survivable* either. Mitigations exist and are standard stack
practice: TEE-backed VTA, witnessed DID (seizure can't silently rotate), and
a mirror at a VTC.

### R2‑12. Moving a room between hosts needs a procedure, not just a property

I3 makes rooms movable in principle (re-point the DID's service endpoint).
In practice: members with cached endpoints hit the old host; the old host
holds ciphertext it should no longer serve (or should it, as a mirror?);
in-flight writes race the move. Needed in the spec: a witnessed *move* log
entry; old-host behaviour after a move (redirect, then refuse); a version
watermark carried in the move entry so the new host provably starts where
the old one ended (same mechanism as R2‑5). Modest, and much cheaper
specified than discovered.

---

## Low / accepted / carried

- **R2‑13 (F15 carried).** Traffic analysis: record sizes, write timing —
  now plus MLS artifacts (commit sizes correlate with tree changes).
  Accepted for v1; padding buckets if a real adversary appears.
- **R2‑14 (F16 carried).** Agents read constantly; read-volume anomaly
  detection is a dead end on every tier.
- **R2‑15 (F8 carried — still the top client-side risk).** Room content is
  untrusted input to every member's agent. A room is a writable channel into
  every reader's model context; provenance marking does not stop a model
  obeying content. Fence as data, show authorship at recall, keep
  contribution explicit. Independent of everything else; land first.
- **R2‑16 (new, human surface).** §6.1 adds human readers: room bodies are
  member-authored markdown rendered in VTC web, mobile, and Cierge surfaces.
  Standard but mandatory hygiene: render inert (no script, no active
  content), sandbox link handling, and treat in-room content as untrusted in
  the *human* direction too — a room is also a phishing channel with a
  trusted-feeling frame. The dual-audience section should say so.

---

## What revision 3 gets right

- **I5 (credential-only authorization) removes an attack class**, not an
  attack: there is no host ACL to confuse, escalate, or drift (the
  `allowed_contexts` bug family cannot exist for rooms).
- **The `private` architecture now stands on published art** — the Signal
  Private Group System proved "server enforces a membership it cannot read"
  at scale; the BBS+ substitution is what buys host-neutral verification.
- **MLS replaces the hand-rolled layer** that v1 found three separate holes
  in (F5/F6/F7 are MLS-native properties), and adds post-compromise security
  the fan-out design could never have.
- **Witnessing converts host misbehaviour from deniable to provable** across
  three findings with one mechanism, and the mechanism ships in the stack
  today.
- **Single write-primary + mirrors** deliberately declines the
  state-resolution problem that consumed Matrix for a decade, while taking
  their hardest-won lesson (self-certifying room identity) as a starting
  condition.
- **The owner is always known.** Still the decision doing the most work:
  accountability, epoch authority, lifecycle addressee, demand recipient —
  the reason an otherwise-opaque system stays operable.

## Recommended order

1. **R2‑2, R2‑8, R2‑9** into the `rooms/*` schemas before they are first
   published — all three are wire-shape commitments.
2. **R2‑1 + R2‑5 + R2‑3's anchor** as one design element (the witnessed
   renewal entry: liveness + version floor + epoch authenticator) in the
   same schema PR.
3. **R2‑7 (witness policy) and R2‑6 (absence definition)** before
   `attributed` ships.
4. **R2‑4's isolation** before any T1 build starts.
5. **R2‑15/F8 now**, against personal memory, independent of everything.
6. **R2‑10, R2‑11, R2‑12, R2‑16** as documentation and procedure alongside
   the tiers they qualify.
