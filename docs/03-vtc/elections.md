# Community elections

A community runs polls, surveys and elections (`vtc/elections/*`, VTI-VOT-001 – 100) with two
parties that never share what they know:

- **The community (this VTC) is the registrar.** It decides who may vote, from its own
  records at the moment each member asks, and issues each of them one **ticket**, blind: it
  signs a request it cannot open, so it never sees the ticket it made.
- **The ballot box is a voting service** (`vti-voting-service`), never this process. It admits
  casts signed by keys made for one cast each, keeps the public (or private) board, and counts.
  It holds no roster and never learns who holds a ticket.

So the community knows who took a ticket and never sees a ballot; the ballot box sees every
ballot and never learns whose it is. Linking a voter to a ballot needs the two to collude.

## Turning it on

1. Build with the `voting` feature (`cargo build -p vtc-service --features voting`). It brings
   the PCS (arkworks) stack, so it is off by default.
2. Name the voting services this community trusts, in `config.toml`. Running one is
   [the voting service](../07-voting/README.md)'s guide:

   ```toml
   [[voting.trusted_ballot_boxes]]
   did = "did:webvh:QmBallots:votes.example.net:b1"
   operator = "Independent Ballots Ltd"
   same_operator = false
   ```

   `operator` and `same_operator` are shown to every member before they take a ticket
   (`Disclosure`, VTI-VOT-090): the separation above is only as good as the two operators'
   independence, so members are told when one party runs both. The list is host configuration:
   a change is a config edit and a restart, never a Trust Task (VTI-VOT-082).
3. Grant `vtc.elections.manage` to whoever runs elections. Community administrators hold it.

The community talks to the ballot box over **TSP, then DIDComm**, signed as itself
(VTI-VOT-005). It needs its signing key, a DID resolver and messaging up; until then a created
election stays `pendingRegistration` and is delivered as soon as they are.

## Running one

| Step | Task | Who |
|---|---|---|
| Create from a manifest | `vtc/elections/create/0.1` | `vtc.elections.manage` |
| Read | `vtc/elections/list/0.1`, `vtc/elections/show/0.1` | managers see all; anyone else an election whose roll admits them now |
| Take a ticket | `vtc/elections/tickets/issue/0.1` | a party the roll admits, once per election — normally through their VTA (`vta/pcs/voter/register`) |
| Close early | `vtc/elections/close/0.1` | `vtc.elections.manage`, only where the manifest allows it |
| Cancel | `vtc/elections/cancel/0.1` | `vtc.elections.manage` |
| Certify the result | `vtc/elections/certify/0.1` | `vtc.elections.manage`, once the ballot box has tallied |

Casting is between the member's VTA and the ballot box (`vta/pcs/vote`, then
`voting/ballot/cast` over HTTPS, the one sessionless door). The community never sees it.

### From the command line

An administrator: `cnm elections create <manifest.json>`, `list`, `show <id>`,
`close <id>`, `cancel <id> --reason …`, `certify <id> [--attestation <vc.json>]…`. The
admin console has the same under **Governance → Elections**.

A member, with their membership persona held by their VTA:

```sh
pnm elections show agm-2027 --vtc https://vtc.example.com/v1 --vtc-did <community DID> \
    --member <your membership DID> --context <the persona's context>
pnm elections vote agm-2027 --answer chair=alice --vtc … --vtc-did … --member … --context …
```

The VTA signs the community's reads and the ticket request as the member
(`vta/pcs/voter/read`, `vta/pcs/voter/register` with `member`), unblinds the ticket, and
builds the cast under a key made for it alone; `pnm` posts the cast to the ballot box from
its own connection after a random pause. Running `vote` again after a lost answer resends;
where the manifest allows, a later vote replaces the earlier one. In a sealed or
tallied-encrypted election the VTA encrypts the ballot (`vta/pcs/vote-encrypted`) under the
election key `show` carries: once the trustees have formed it, the community reads the board,
verifies every step of the ceremony as its trustee's signed request, and keeps the key only if
those steps form it — never a key the ballot box merely reports. A voter never
needs to read the board for it, so this works on a private board too, where the trustees read
their own ceremony and nobody else outside the community and its auditors reads anything.

### What the community checks on create

The manifest must be valid as the ballot box would judge it, this community's own, name a
trusted ballot box, and use an identifier the community has not used. A sealed or
tallied-encrypted manifest names its trustees (`trustees.dids`, `threshold`): at least two, the
threshold at least two, and neither the community nor the ballot box among them; it allows no
running totals, and a tallied-encrypted one asks choice questions only (VTI-VOT-061 – 064). It is then recorded and registered **remote first**:
`registered` only once the ballot box said so; refused at once means nothing is kept
(`ballotBoxRefused`); no answer leaves it `pendingRegistration`, and the community's own sweeper
is the one retry owner, with a capped backoff. No ticket is issued before registration.

### Binding elections take two

A manifest with `binding: true` says the result decides something in the community's name. Its
creation is parked for another holder of `vtc.elections.manage` (VTI-VOT-081), after the
requester's own bound step-up, and runs itself on approval with every check above run again.
The action list shows it as `election.binding.create`.

### Tickets

One per party per election, recorded before the answer, under one lock so two requests cannot
both pass the "none held yet" check. A resend of the same signed request is answered with the
first answer. The audit row names the party and the election, and nothing derived from the
request: the identifier, the commitment and the pre-credential are exactly what a later
deanonymisation would join a ticket to its holder by. The stored pre-credential is discarded
once voting closes.

An election a caller may not see answers `electionUnknown` — the same as one that does not
exist — so a member learns nothing about an election that is not theirs.

### Checkpoints

The community reads and keeps the ballot box's signed board head when voting opens, every six
hours while it is open, and at close. Certification proves the final board consistent with
every one, so a ballot box that rewrote its board after a checkpoint is caught.

### Certification

`certify` reads the result, the head and every entry from the ballot box itself — never from
the requester — and re-verifies the whole board from the community's own voting key
(`vti_voting::audit`, which any auditor can run too): the entries hash to the head, the board
extends every checkpoint, every cast would have been admitted, every tag counts once and
replacements follow the manifest, the result is the board's, and there are no more ballots than
tickets issued (VTI-VOT-072). Auditors' attestations — credentials from DIDs the manifest names
in `board.auditors`, attesting the election and the head the result counts — are verified and
kept beside it, never instead of it. A certified result authorizes nothing by itself.

### Sealed and tallied-encrypted elections

The trustees generate the election key on the board before voting opens (`voting/trustees/*`,
each trustee's VTA holding its keys — see [the trustee's round](../02-vta/pcs-engine.md#the-trustees-round)).
A trustee takes part with `pnm elections trustee step <election> --watch`, started once the
election is registered and left running until the result is out.
If no key has formed by `votingOpens`, the ceremony has failed: no cast is admitted, and the
community cancels the election. The key forms only from at least `threshold` qualified dealers
and confirmations, so no single trustee can be left holding it. Voters cast with
`vta/pcs/vote-encrypted`, their VTAs forming the key from the signed steps `vtc/elections/show`
carries (`ceremony`). After close the community computes the decryption targets from the board
it verified and signs them (`voting/trustees/authorize`, sent by the sweeper); any `threshold`
trustees then decrypt that set and nothing else, and the ballot box publishes the result — every sealed ballot
opened (or marked spoiled, uncounted, when it does not open to a valid ballot), or each
option's total and nothing else. Every step of the ceremony is on the board as the trustee's own
signed request (a `trusteeStep` entry, CONVENTIONS §9.6), and the community verifies each proof
against the trustee's DID: a ballot box that dealt in a trustee's name, to hold the election key
itself, would have to sign as that trustee. Certification re-runs all of it from the board: the
ceremony, every step's signature, every cast's attestation over its encrypted form and a tallied ballot's proofs, every partial
decryption, and the openings and totals they give — and the board's order (CONVENTIONS §3.9):
nothing cast after the close, the authorization after the close and before any partial, one
result, last, over the board before it (`orderInvalid` / `ceremonyInvalid` faults).

## Code

`vtc-service/src/elections/` (`store`, `link`, `ops`, `sweeper`), `vti-voting/src/audit.rs`,
`vtc-service/src/trust_tasks/election_tasks.rs`, `vtc-service/tests/it/election_tasks.rs`.
The protocol core is the `vti-voting` crate; the ballot box is `vti-voting-service`.
