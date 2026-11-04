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
   a change is a config edit and a restart, never a Trust Task (VTI-VOT-082). Holders of
   `vtc.elections.manage` read it with `vtc/elections/ballot-boxes/list/0.1` — exactly the list
   `create` checks against — which the console's manifest builder offers as a choice and
   `cnm elections ballot-boxes` prints.
3. Grant `vtc.elections.manage` to whoever runs elections. Community administrators hold it.

The community talks to the ballot box over **TSP, then DIDComm**, signed as itself
(VTI-VOT-005). It needs its signing key, a DID resolver and messaging up; until then a created
election stays `pendingRegistration` and is delivered as soon as they are.

## Running one

| Step | Task | Who |
|---|---|---|
| Read the trusted ballot boxes | `vtc/elections/ballot-boxes/list/0.1` | `vtc.elections.manage` |
| Create from a manifest | `vtc/elections/create/0.5` (0.4 and 0.3 still served) | `vtc.elections.manage` |
| Read | `vtc/elections/list/0.5` (0.3 still served), `vtc/elections/show/0.6` (0.3 and 0.2 still served) | managers see all; anyone else an election whose roll admits them now — see [Credential rolls](#credential-rolls) for an election put to a member party |
| Take a ticket | `vtc/elections/tickets/issue/0.3` (0.1 still served) | a party the roll admits, once per election — normally through their VTA (`vta/pcs/voter/register`) |
| Close early | `vtc/elections/close/0.1` | `vtc.elections.manage`, only where the manifest allows it |
| Cancel | `vtc/elections/cancel/0.1` | `vtc.elections.manage` |
| Certify the result | `vtc/elections/certify/0.1` | `vtc.elections.manage`, once the ballot box has tallied |

Casting is between the member's VTA and the ballot box (`vta/pcs/vote`, then
`voting/ballot/cast` over HTTPS, the one sessionless door). The community never sees it.

### Writing the manifest in the console

**Governance → Elections → New election** builds the manifest step by step — about, questions,
who votes, schedule, counting — and ends on a review that shows the manifest, a plain-language
summary and the digest every ticket and vote will be bound to. It checks as you go what the
community would otherwise refuse with `invalidManifest`: the schema's bounds and the rules
between fields (times in order and still ahead, a choice's bounds within its options, unique
question and option keys, the trustee rules of a sealed or totals-only election, an auditor or
trustee that is the community or the ballot box). Create stays disabled until the review is
clean. The community checks everything again on create; the form's checks are a convenience,
not the authority.

*Start from a previous election* copies one's questions, voters and counting into a fresh
identifier and schedule. The **JSON** view is the same manifest as text: anything written there
comes back into the form, except a manifest carrying something the form does not edit, which
stays in the JSON view rather than being trimmed. The unfinished draft is kept in the browser
tab until it is created or discarded.

### From the command line

An administrator: `cnm elections ballot-boxes`, `create <manifest.json>`, `list`, `show <id>`,
`close <id>`, `cancel <id> --reason …`, `certify <id> [--attestation <vc.json>]…`. The
admin console has the same under **Governance → Elections**.

`cnm elections manifest init --ballot-box <DID> [--id …] [--title …] [--out <file>]` writes a
starting manifest for the community — one yes/no question, open voting by its members for a
week from tomorrow — and `cnm elections manifest check <file>` checks one offline, printing its
digest: the schema of `vtc/elections/create/0.4`, then `vti_voting::rules::check_new_manifest`
(the same function the community runs on create: the rules between fields and voting not
already closed), then that it names this community. Only what needs the community itself — a
trusted ballot box (VTI-VOT-082) and an unused identifier — waits for `create`. Neither command
opens a session; the community's DID comes from `--vtc-did` or the profile.

### Voting from the member portal

A member with the [VTA Wallet browser extension](website-and-admin.md#member-portal) votes from
the portal's **Elections** page (`/members/#/elections`): it lists the elections the roll admits
them to, shows each one's questions and disclosure, and hands off to the wallet to take a ticket
and to vote. The ballot is filled in the wallet's own window, never the portal's page — the
portal is this community's code, and the community never sees a ballot — and the wallet sends
the cast to the ballot box itself, after a random pause, as `pnm` does. The page is not told
whether a vote was cast. The wallet must be allowed to reach the ballot box's address (the
`TrustTaskHTTPS` service in its DID document) from its popup.

Beside the community's own list, the page shows the elections the member's agent holds a
[notification](notifications.md) of from this community (VTI-NTF-063) — one the community's list
does not show them, such as an election put to the members of a party that is itself a member of
the community (VTI-VOT-015), and a mark on a listed one. Until the member opens it the page sees
only what the notification says: the election's identifier, the party it is put to, the voting
period and whether the notice was withdrawn. Opening one passes that party to the wallet as
`memberOf` for show, ticket and vote; the wallet asks the member in its own window before it
presents the membership credential that party issued, and presents no other (VTI-VOT-016). The
page presents nothing itself. A withdrawn notice cannot be opened from the page. The community's
`electionUnknown` (the same answer whether the election does not exist, is not open to the
member, or is put to a party whose membership was not shown) and `indeterminate` (a check it
could not complete, which records nothing) are shown in words. A wallet that predates
notifications lists as before and is never sent `memberOf`.

### From the command line, as a member

A member, with their membership persona held by their VTA:

```sh
pnm elections show agm-2027 --vtc https://vtc.example.com/v1 --vtc-did <community DID> \
    --member <your membership DID> --context <the persona's context>
pnm elections ticket agm-2027 --vtc … --vtc-did … --member … --context …
# later — after voting opens, and not straight after the ticket
pnm elections vote agm-2027 --answer chair=alice --vtc … --vtc-did … --member … --context …
```

Taking the ticket and voting are separate runs: the community knows when it issued a ticket and
the ballot box when a cast arrived, so a cast sent straight after its ticket can be paired by
time. `vote` with no ticket held takes one and stops; `--now` casts in the same run anyway.

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

### When written answers are released

A text question's answers are disclosed only once `textReleaseThreshold` ballots are counted,
and never in a count taken while voting is open (VTI-VOT-065). The threshold may be anything
from 1; 10 or more is advised, and the console's builder starts at 10. A written answer can
identify its author by what it says or how it is phrased, and the fewer ballots released
together, the easier that is. So below 10:

- the builder warns the administrator in **Counting** and again in **Review**
  (`vtc/elections/create/0.4` says a composing client should);
- the election page's **What members are told** says when written answers are released, with
  the same warning;
- every member is told before they take a ticket (VTI-VOT-090): `pnm elections show` and
  `ticket` print it, and the wallet and portal derive it from the manifest's
  `textReleaseThreshold` — the disclosure itself carries no separate member for it.

The manifest a threshold below 10 can travel in is voting/_shared/0.3: `vtc/elections/create/0.4`
and `show/0.3`, `voting/election/register/0.3` and `show/0.3`, and the `vta/pcs/*` versions
that carry it (`voter/register/0.3`, `vote/0.3`, `vote-encrypted/0.4`, `trustee/enrol/0.3`,
`trustee/{deal,keys,justify}/0.4`; `voter/read/0.3` and `trustee/read/0.3` sign the 0.3 shows).
The previous versions stay served for clients that send them, and their schema still holds the
threshold to 10: `create/0.3` refuses a lower one as a malformed request, and `show/0.2`
answers an election below 10 with `unsupportedVersion`, naming 0.3. An election of 10 or more
reads the same at either version — the manifest's members, and so its digest, do not change.

The community registers an election with its ballot box at `voting/election/register/0.4`. A
ballot box from before that version refuses it `unsupportedVersion`; the community then
registers at 0.3 an election without a credential roll, and at 0.2 one of 10 or more, and an
election neither can carry is refused (`ballotBoxRefused`) until the ballot box is upgraded.

### Credential rolls

A fourth roll rule, `credential` (voting/_shared/0.4, VTI-VOT-021, VTI-VOT-025), puts a question
to the holders of a membership credential for **one DID**, named in `roll.memberOf`: this
community, one of its groups, or a party that is itself a member of this community — another
community, a group of one, or a network. `memberOf` is always a DID, never a group's local
identifier; it is present exactly when the rule is `credential`, and `listed` never is.

**Who it can name** (create/0.5 Conformance item 6, VTI-VOT-026). The community, one of its groups
(by the group's own DID), or a party that is an active member of this community — its entry
live, not suspended, not an `application`, its member record not removed — holding a
membership credential this community issued it whose slot in the community's own revocation
list is clear. Anything else is refused `rollUntrusted` and nothing is recorded; recognition
through a trust registry is not membership. Which of the three it was is recorded with the
election, so a group deleted afterwards is never mistaken for a party outside the community
(VTI-VOT-029).

**Eligibility is proven at the claim, never fixed at creation.** A member claiming a ticket
presents, in the `tickets/issue/0.3` request itself, a Verifiable Presentation of their
membership credential for `memberOf`, bound to that request (`nonce` = the request's `id`,
`domain` = the community's DID) and made by the credential's subject, who signs the request.
So a member who joins after the election is called is admitted, and one removed since is not.
The community cannot state a roll size, and reports turnout against the tickets it issued
(VTI-VOT-028). One ticket per credential subject (VTI-VOT-027); for the community's own roll
and its groups' the subject is the member's membership DID, and a rotation carries the ticket
(VTI-VOT-022).

**What is checked, in order** (tickets/issue/0.3 items 2 – 7):

1. *Before the election is looked up, and without reference to it* (VTI-VOT-018): the
   presentation's binding, its holder (the signer, one credential, about the signer), the
   issuer's proof, the validity period, and its status. A credential this community issued is
   checked against its own status list; any other's list is fetched. Where a DID document or a
   status list cannot be obtained and no check failed, the answer is the framework's
   **`indeterminate`** (retryable), identically whatever `electionId` names, and nothing is
   recorded: the client resends the same document later, with backoff.
2. The election is known and the signer may see it (below).
3. Issuance is open, the manifest is the one read.
4. Under `credential`, reading only the community's own records: a presentation is carried
   (`presentationRequired`); `memberOf` is still trusted — the group still held, the member
   party's membership still active (`rollUntrusted`); the credential proves the membership —
   item 1's checks, an issuer that is exactly `memberOf`, and for a group the community's
   authority credential to it still live (`membershipNotProven`, with `details.reason`);
   nothing revoked (`membershipRevoked`); and, for the community or a group, the records still
   hold the signer as an active member, of the group too (`notEligible`).
5. No ticket held for that subject (`alreadyIssued`).

The presentation is never kept; the issuance record holds the party, and the audit row the
credential's issuer, never the presentation or the credential (VTI-CRD-042).

**The member party is notified** (VTI-NTF-060, VTI-NTF-061). Once the ballot box has registered
an election under a roll naming a member party, the community sends that party — and nobody else —
a `notifications/notify/0.1` of the kind `election`: the community, the election's identifier,
`vtc/elections/show/0.6` to open it, the party as audience and the voting period, nothing else of
the election. If the election is cancelled or closed before voting closes, a higher revision
withdraws it. The election sweeper sends both, through the durable member push; whether the party
passes it on to its members is the party's decision ([Notifications](../02-vta/notifications.md)).

**Who sees such an election** (VTI-VOT-015, VTI-VOT-016, VTI-VOT-017). Under a roll naming the
community or a group, those its records show the roll could admit — every active member, or the
group's active members — as for any other roll. Under a roll naming a **member party**, the
community holds no record of that party's members, so:

- `list` shows it only to managers and to the party itself, never to anyone else, not even
  as a stub of its identifier;
- `show/0.6` shows it to anyone else only on a presentation in that read that passes the same
  checks a claim makes — accepted once per document, the read's `id` kept only for the
  acceptance window;
- `tickets/issue/0.3` answers every other outcome for such a signer — no presentation, a
  failed one, one another party issued, a party whose own membership has lapsed —
  `electionUnknown`, decided before the election's state or manifest is compared.

A party's member therefore learns of such an election from outside the community's list: from
the party, which the list does show it to (a notification, VTI-NTF-060 – 063, is the coming
mechanism), or from a link. Reading it already shows the community their membership of that
party, before they have seen what it asks, and the wallet tells them so.

**A deleted group** (VTI-VOT-029): the election is shown only to managers, who must cancel
it; a manager's claim is refused `rollUntrusted`, anyone else's `electionUnknown`.

**What members are told** (VTI-VOT-090): `show/0.6`'s `disclosure.rollCredential` names
`memberOf`, what it is to the community (`thisCommunity`, `communityGroup`, `memberParty`), its
name where the reader may know it (a group's, to a manager or for a group every member can see),
and that claiming a ticket shows the community the claimant's membership of it
(`presenterDisclosed`). The console's election page, `pnm elections show` and the portal show
it.

**Versions.** A credential roll travels only in voting/_shared/0.4: `create/0.5`, `show/0.6`,
`voting/election/register/0.4` and `show/0.4`, and the `vta/pcs/*` versions that carry it.
`show/0.3` and `0.2`, and `tickets/issue/0.1`, which carry no presentation, refuse a
credential-roll election `unsupportedVersion`, once the caller may see it. The community
registers at `voting/election/register/0.4`; a ballot box from before it refuses by version,
and the community falls back to 0.3 for a manifest without a credential roll (then to 0.2 as
below).

**Not yet:** a trust registry as a status source (only status lists are read), a predicate
proof of membership under an election-scoped pseudonym (the specification's open issue), and
the `notifications/*` family.

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
exist — so a member learns nothing about an election that is not theirs. Under a credential roll
a claim carries a presentation, checked first (see [Credential rolls](#credential-rolls)).

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
If no key has formed by `votingOpensAt`, the ceremony has failed: no cast is admitted, and the
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

### After a board is deleted

An election opened on a community board that is later deleted keeps only a tombstone: its
identifier, manifest digest, ballot box and the board heads the community kept
([boards.md](boards.md), VTI-BRD-007 – 009). `vtc/elections/show` no longer knows it; read the
tombstone with `vtc/elections/tombstones/show` (`cnm elections tombstone <election-id>`) for as
long as `[boards] tombstone_retention` keeps it.

## Code

`vtc-service/src/elections/` (`store`, `link`, `ops`, `sweeper`), `vti-voting/src/audit.rs`,
`vtc-service/src/trust_tasks/election_tasks.rs`, `vtc-service/tests/it/election_tasks.rs`.
The protocol core is the `vti-voting` crate; the ballot box is `vti-voting-service`.
