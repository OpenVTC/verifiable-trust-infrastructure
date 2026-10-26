# Community voting: threat model and the review of October 2026

Community voting (VTI-VOT-001 – 100) spreads one election over four parties: the **community**
(registrar: the roll, the tickets, certification), the **ballot box** (`vti-voting-service`:
casts, the board, the result), the **trustees** (each a persona in its own VTA, holding a share
of the election key) and the **voters** (each casting through their own VTA). This note records
what each party is trusted with, the attacks an adversarial review of the first implementation
found, and what is still open.

Specifications: `voting/*` and `vta/pcs/{vote,vote-encrypted,trustee/*}` in the Trust Task
registry, `voting/_shared/0.1/CONVENTIONS.md`. Operator guides: `docs/07-voting/README.md`,
`docs/03-vtc/elections.md`, `docs/02-vta/pcs-engine.md`.

## Who is trusted with what

| Party | Trusted to | Never trusted to |
|---|---|---|
| Community | admit the roll; issue one ticket per party | learn how anyone voted; link a ticket to a cast |
| Ballot box | stay available; keep what it accepted | report a key, a complaint, a dealing, a decryption target or a total that the signed board does not prove |
| Trustees | fewer than `threshold` of them collude | — (a `threshold` coalition can decrypt anything; that is the definition) |
| Voter's VTA | keep the member's keys and choices | — (it is the member's own agent) |

The rule that follows: **every party acts on signed evidence, verified itself, never on another
party's report of it.** The board is the evidence; the ballot box is only its keeper.

## What the review found, and the fix

| # | Attack | Fix |
|---|---|---|
| 1 | The box reports substitute transport keys; trustees seal shares to keys the box holds | trustees act on the signed enrolments in `steps`; deal pins the set (`ceremonyChanged`) |
| 2 | The box invents complaints; trustees reveal shares in answer | justify needs the complainant's own signed confirm (`noComplaint`) |
| 3 | The box replays a dealing to overwrite a key share | keys never replaces a held share (`keyMismatch`) |
| 4 | The box lists one voter's ciphertext as a "total" and collects the partials | the community computes the targets from the board it verified and signs them (`voting/trustees/authorize`); a trustee decrypts only an authorized set, once |
| 5 | One trustee complains of every other dealer late, and holds the key alone | the key forms only from ≥ `threshold` qualified dealers and confirmations (§9.6 item 5) |
| 6 | The community or box hands one voter a key it holds | the voter's VTA forms the key from the signed steps (`vote-encrypted/0.2`) |
| 7 | A voter re-casts a target's encrypted ballot under their own ticket and reads the vote off the totals (Cortier–Smyth) | proofs and the seal's AAD bind the cast's tag; the box and the audit refuse a ciphertext already on the board |
| 8 | A board with casts after the close, or a result before it, certifies | §3.9 board order, checked at certification (`orderInvalid`, `ceremonyInvalid`) |
| 9 | A rotated member gets a second ticket under the new DID | the rotation carries the tickets (VTI-VOT-022) |
| 10 | A cast signed by a `did:webvh` makes the box fetch an attacker's URL | casts must be `did:key`; signed requests name `recipient`; consequential ones carry `issuedAt` |
| 11 | A malformed payload reaches the state machine | the box validates every payload against its schema first |
| 12 | A torn receipt record misaligns every later receipt | the journal truncates a torn tail, as it does for entries |
| 13 | A box restarted between the last partial and the result never finishes | restore resumes the decryption |
| 14 | `pnm elections vote` took the ticket and cast in one run, so the community and the box could pair them by their clocks | `pnm elections ticket` is its own step; `vote` with no ticket held takes one and stops unless given `--now` |
| 15 | The voter's VTA kept the member-signed ticket request beside the casts' leaf hashes, readable without the seed, and never discarded either | the member's documents go once the ticket is held; leaf hashes and receipts are wrapped; the sweeper discards the ticket at the close and the rest 30 days later |
| 16 | Restoring a VTC backup forgets the tickets issued after it, so their holders take a second and vote twice | a restore closes issuance for good on every election whose registration had opened and whose voting had not closed; the remedy is to cancel and create it again |
| 17 | Any DID registers elections at a box until its store is full | `[communities] allowed` (none without it) and a quota of unfinished elections per community (`unavailable` past it) |
| 18 | A flood of casts holds the box's one lock through every pairing check, stalling every other community | a cast's costly checks run on bounded blocking threads without the lock; what they prove admits that one cast only |
| 19 | One `voting/board/read` of a board of large entries is an unbounded answer | a page carries at most 256 KiB of entries (at least one), fewer than `limit` |
| 20 | A box dates its heads ahead, and the community, pacing checkpoints by a head's `issuedAt`, stops taking them — leaving the box free to show different boards in between | checkpoints are paced by when the community last had a head answered, by its own clock |

Items 1 – 8 changed the wire, as `vta/pcs/trustee/*/0.2`, `vta/pcs/vote-encrypted/0.2`,
`voting/trustees/authorize/0.1` and CONVENTIONS §3.9 / §9.3 – 9.7. The 0.1 trustee and
vote-encrypted tasks are retired: their whole design was acting on the box's report.

## Still open

None of these lets a single party change a result. Each one weakens privacy or availability, or
leaves a cost unbounded:

- **The cast door's rate.** The service does not rate-limit the anonymous HTTPS door itself;
  the guide puts that on the reverse proxy in front of it.

## Considered, and left as they are

- **The ticket's class names the election, not its manifest** (`voter/<electionId>`). The cast
  binds the manifest anyway: the point a cast attests for, and the context its attestation is
  made under, both hash the manifest digest, so a ticket counts once per manifest. Using one
  ticket under two manifests needs the community to register the same election identifier
  twice, at two boxes, with different manifests — two elections it runs itself, each counted
  apart. A community that wants a voter to count twice can issue a second ticket; the label
  changes nothing about that.
- **The voter's VTA takes the voting key from the community, unchecked against the box.** A
  ticket under any key but the one the box registered is refused at the cast (`castInvalid`):
  the member sees the refusal, nothing links them to it, and a community that wants to keep a
  member from voting can already refuse the ticket. Checking would need `voting/election/show`
  to carry the parameters, and a private board answers no voter anyway. Where the community's
  operator also runs the box, the box could admit casts under a second key; that is the
  `sameOperator` disclosure every member is shown before taking a ticket (VTI-VOT-090).
