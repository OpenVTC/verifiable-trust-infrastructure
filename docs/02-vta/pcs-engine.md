# The VTA as hidden-vetting (PCS) engine

A community can run **hidden vetting**: it admits an applicant on a zero-knowledge
proof that enough distinct eligible vetters vetted them, and learns nothing about
*which* vetters did. The proof rests on a predicate credential system (PCS). The
community is the scheme's *helper*; every vetter and every applicant holds a PCS
secret key, `usk`, from which each tag and proof they make is derived.

The VTA can hold those keys for its principal and run every member-side PCS
operation. The client — a wallet, a desktop agent — carries messages between the
VTA, the community and the other party, and **never holds a `usk`**. That is what
lets a client with no PCS implementation, such as a mobile wallet, apply to (or vet
for) a community that runs hidden vetting.

- Specifications: `vta/pcs/*/0.1` in the Trust Task registry, with the family's
  rules in `vta/_shared/0.4/CONVENTIONS.md`
  (trustoverip/dtgwg-trust-tasks-tf #756).
- Design: `vetting-hidden-vetters-pcs.md` §13 C7 (*the VTA is the PCS engine*).
- Engine: `vti-vetting-pcs` (`vetter`, `applicant`); VTA slice:
  `vta-service/src/{operations,trust_tasks}/pcs.rs`.

## The applicant's round

| Step | Who | Task |
|---|---|---|
| 1 | client → VTA | `vta/pcs/applications/create` — the VTA derives a fresh key for this application and returns its handle and PCS identifier `id` |
| 2 | client → vetter | `vetting/request`, carrying `{suite, id}` in its `ext` under the community's hidden-vetting namespace |
| 3 | vetter → client | `vetting/attestation`, after the session |
| 4 | client → VTA | `vta/pcs/verify-attestation` — checked on arrival, kept for the proof |
| 5 | client → community | `vtc/vetting/pcs-challenge` — a single-use challenge |
| 6 | client → VTA | `vta/pcs/prove` — the proof, bound to the challenge, the requirements digest and the join DID |
| 7 | client → community | the join submission, with the proof as `extensions.hiddenVetting` |
| 8 | client → VTA | `vta/pcs/applications/delete` once the application is decided |

## The vetter's round

| When | Tasks |
|---|---|
| Enrolment, once per vetting period | `vta/pcs/root-request` → `vtc/vetting/vetters/pcs-root` at the community → `vta/pcs/root-accept` |
| Every tick of the drip | `vta/pcs/tokens/request` → `vtc/vetting/vetters/pcs-tokens` → `vta/pcs/tokens/accept` (or `vta/pcs/tokens/abandon` when the community refuses the draw) |
| After a session | `vta/pcs/attest` → `vetting/attestation` to the applicant |
| Any time | `vta/pcs/vetter/show` |
| After `pcs-root:identifierRebound` | `vtc/vetting/vetters/pcs-binding/show` at the community for `boundId` → `vta/pcs/vetter/recover` → enrol again |

The drip is unconditional by design: a vetter draws on its schedule whether or not
it has vetted anyone, because a draw that tracked activity would report activity.

The first `root-request` for a context and community creates the vetter engine and
records the member DID. The engine keeps **one key for its whole life** — a vetter
with two keys would count as two vetters in one proof — and a later `root-request`
naming another member DID is refused `memberMismatch`.

### Recovering the bound key

If the engine record is lost or replaced while the seed survives (a re-created
engine, a VTA restored without the record), the next `root-request` makes a fresh
key and the community refuses it with `pcs-root:identifierRebound`. The bound key
is still derivable. `vta/pcs/vetter/recover` takes the identifier the community
bound (`boundId`) and searches the keys the VTA can derive for the context:

- every path the context's counter has handed out, under every seed generation
  still held (a retired generation whose archive cannot be read is skipped), less
  the paths another PCS engine record names;
- at most `vta_keys::custody::PCS_SEARCH_MAX_DERIVATIONS` (4096) derivations. A
  context with more candidates is refused `notFound`, saying so, rather than
  searched in part;
- through `key_custody::search_pcs_member_keys`, which holds every candidate
  inside the context's base, loads each seed generation once, never returns a
  seed, and audits the search once (`key.pcs_search`: how many keys were derived
  and whether one matched — no path, seed or identifier).

The engine's key is replaced only while it holds nothing a community issued (no
class credential, token or attestation; otherwise `engineEnrolled`). Enrolments
and draws in flight under the replaced key are discarded. An identifier held by
an engine in another context the caller can act in is refused
`heldInAnotherContext`, naming that context.

## Custody

- **No `usk` is stored.** A member key is a pure function of the seed and a path
  under its context's base (VTI-KEY-030), allocated from the counter key records
  use, so no key record can ever be given the same path. It is rebuilt on every use
  through `key_custody::derive_pcs_member_seed`, which holds the path to its
  context. The seed it derives is domain-separated (`vta/pcs/member-key/v1`) from
  the Ed25519 node at that path.
- **No task returns a key, a class credential, an unspent token, or the blinding
  state of a request in flight.**
- **Everything else secret is wrapped** under the seed-derived KEK (the one imported
  keys use) in the `pcs_engine` keyspace. The keyspace is backed up: an applicant's
  attestations cannot be replaced without its vetters sitting again.

## Authorization

| Capability | Tasks | Derived by |
|---|---|---|
| `pcs-vetter` (`pcsVetter`) | `root-request`, `root-accept`, `tokens/*`, `attest`, `vetter/show`, `vetter/recover` | `admin`, `initiator` |
| `pcs-applicant` (`pcsApplicant`) | `applications/*`, `verify-attestation`, `prove` | `admin`, `initiator` |
| `pcs-voter` (`pcsVoter`) | `voter/register`, `voter/read`, `voter/accept`, `vote`, `vote-encrypted`, `voter/receipt`, `voter/receipts/list` | `admin`, `initiator` |
| `pcs-trustee` (`pcsTrustee`) | `trustee/enrol`, `trustee/deal`, `trustee/keys`, `trustee/justify`, `trustee/decrypt` | `admin`, `initiator` |

None is `sign`, and `sign` confers none (VTI-VTA-007). `application`
derives neither: an agent vets or applies for its principal only when granted the
capability by name. Every task is also gated on the context: a vetter task, and
`applications/create`, name it; an application handle in a context the caller
cannot act in reads as `notFound`.

`vta/pcs/attest` is the vetter's word that a person was checked. To require a
step-up or another person's consent before it runs, add an approvals rule on its
type URI ([Approvals](approvals.md)):

```sh
pnm approvals require https://trusttasks.org/spec/vta/pcs/attest/0.1 --reauth
```

## The voter's round

The same engine votes in a community's elections (community voting, VTI-VOT-020 –
053; conventions `voting/_shared/0.1/CONVENTIONS.md`):

| Step | Who | Task |
|---|---|---|
| 0 | client → VTA → community | `vta/pcs/voter/read` — `vtc/elections/list` or `show` signed as the member (a persona this VTA holds), sent to the community unchanged: the manifest, parameters and disclosure the next steps need. The VTA signs only those reads, and `vtc/elections/tombstones/show` (step 7) |
| 1 | client → VTA | `vta/pcs/voter/register` — a fresh key for this election and the blinded ticket request; a repeat before the ticket is held answers with the same request. With `member` (a persona this VTA holds), also `ticketDocument`: the request to the community already signed as that member, kept and returned unchanged on a repeat |
| 2 | client → community | `vtc/elections/tickets/issue` — `ticketDocument` as it came (or the request signed by a member DID the client holds); the community signs the ticket blind, one per eligible member |
| 3 | client → VTA | `vta/pcs/voter/accept` — unblinded and kept wrapped |
| 4 | client → VTA | `vta/pcs/vote` — the ballot checked against the manifest, the cast built, and the `voting/ballot/cast` document returned **signed by a key made for that cast alone** and never kept |
| 5 | client → ballot box | the cast document, from the client's own connection, after a pause; resent unchanged if the answer is lost |
| 6 | client → VTA | `vta/pcs/voter/receipt` — the ballot box's signed receipt kept, and checked for inclusion in a head the community kept |
| 7 | client → VTA → ballot box → VTA | after close (VTI-VOT-053): `vta/pcs/voter/receipts/list` returns the receipts kept and the ballot box; the client reads the head the community kept at close from `show` — or, once the election's board is deleted, from `vtc/elections/tombstones/show` (VTI-BRD-009) — fetches each cast's `voting/board/inclusion` from the ballot box over its own connection, unsigned, with the receipt's token, and hands both to `voter/receipt`, which answers `included` or `notIncluded`. A head smaller than the cast's leaf omits it, with no path to fetch |

**Versions.** The voter and trustee tasks that carry the manifest take voting/_shared/0.4's,
whose roll may be a **credential roll** (`roll.rule: credential`, `roll.memberOf` a DID;
VTI-VOT-025) and whose `textReleaseThreshold` may be as low as 1 (VTI-VOT-065):
`voter/register/0.5`, `vote/0.4`, `vote-encrypted/0.5`, `trustee/enrol/0.4` and
`trustee/{deal,keys,justify}/0.5`. `voter/register/0.5`'s `ticketDocument` is a
`vtc/elections/tickets/issue/0.3` request; `voter/read/0.7` signs `vtc/elections/list/0.5`,
`vtc/elections/show/0.6` or `vtc/elections/tombstones/show/0.1`, and `trustee/read/0.4` signs `voting/election/show/0.4`. The previous
versions are still served, each held to its own schema and answering in its own shape:
`voter/register/0.3` and `0.2` build a `tickets/issue/0.1` request (kept apart from 0.5's, so
each version's repeat answers with its own document), `voter/read/0.6` signs `list/0.5` or
`show/0.6` and no tombstone, `voter/read/0.3` signs `list/0.3` or
`show/0.3`, `0.2` `list/0.3` or `show/0.2`, and `trustee/read/0.3` and `0.2` the show they name.
A client showing a member an election before the ticket says so when the threshold is below 10,
and that a written answer may identify its author (VTI-VOT-090); it reads that from the manifest.

**Credential rolls.** Under a credential roll the community admits a voter on a presentation of
their membership credential for `roll.memberOf` — the community, one of its groups, or a party
that is itself its member — checked when the ticket is claimed (VTI-VOT-025). The client names
the credential the member chose, by its vault handle:

- `voter/register/0.5` with `member` and `membershipCredential`: the engine refuses
  `membershipCredentialRequired` for a credential roll without one (or one given without
  `member`, or under any other rule) and `membershipCredentialUnusable` for a credential it
  holds no usable one under — not in the vault, not presentable by the caller as `member`, not
  about `member`, not issued by `roll.memberOf`, revoked or outside its validity period —
  before anything is allocated. Then `ticketDocument` carries `presentation`: a Data Integrity
  presentation of that one credential, made as `member`, with `nonce` the document's `id` and
  `domain` the community, disclosing no more than the credential's whole subject requires (a
  Data Integrity credential cannot withhold a claim; an SD-JWT discloses none of its selective
  ones). The presentation is recorded as a disclosure in the vault, as `vault/credentials/present`
  records one.
- `voter/read/0.6` with `read: show`, `membershipCredential` and `memberOf`: to read an election
  put to the members of a party that is itself a member of the community, which the community
  shows nobody else (VTI-VOT-015). The engine presents only a credential whose issuer is
  `memberOf`, compared character for character, and refuses any other
  `membershipCredentialMismatch` — a credential from a group of `memberOf` included — so a
  client that names the wrong credential cannot make the engine show the community a membership
  unrelated to the election (VTI-VOT-016). A payload carrying its own `presentation` is
  `malformedRequest`: only the engine builds one, bound to the document it signs. Reading this
  way shows the community the membership before the member has seen the election; the client
  says so first (VTI-VOT-090).

**`indeterminate`.** A community verifies a presentation before it looks the election up, and
answers a check it could not complete — the issuer's DID document, a status list or a trust
registry it could not obtain — with the framework's retryable `indeterminate`, whatever the
election (VTI-VOT-018). Nothing was recorded: the client sends the **same** document again, after
any `retryAfter` and with backoff, while it is unexpired — for a ticket, `voter/register` returns
the kept `ticketDocument` unchanged. It never reads `indeterminate`, or `electionUnknown`, as a
statement that no election exists. After a *lost* answer to a read it asks for a new read, as the
community accepts a presentation in one document once.

A voter key is per election, so a key recovered later links one election, never a
member's voting history. The cast never carries the member's DID (VTI-VOT-003), and
audit names the election, never a tag, a cast or a receipt (VTI-VOT-100). An MCP
host confirms every `vote` (`vta-mcp`'s guard counts it destructive).

Steps 0 – 3 and 4 – 6 belong in separate runs, apart in time (CONVENTIONS §6 item 3): the
community knows when it issued the ticket and the ballot box when the cast arrived. `pnm
elections ticket` takes the ticket alone; `pnm elections vote` with no ticket held takes one
and stops unless given `--now`. Under a credential roll, `pnm elections ticket <id>
--membership-credential <handle>` presents that credential, and with `--member-of <did>` its
read presents it too; `pnm elections show` takes the same two flags.

What the VTA keeps never pairs the member with a cast without the seed: the documents signed
as the member go once the ticket is held, and the casts' leaf hashes and receipts are wrapped
like the ticket. The storage sweeper discards the ticket when voting closes, and the record,
casts and receipts 30 days later (`pcs_voter::RECEIPT_RETENTION`), with the voter key's path;
CONVENTIONS §5 item 3.

In a **sealed** or **tallied-encrypted** election (VTI-VOT-060 – 064, conventions §9) step 4
is `vta/pcs/vote-encrypted/0.5` (0.4 and 0.3 still served), given the ceremony `vtc/elections/show` carries — the
trustees' signed steps, from which the VTA forms the election key itself (at least `threshold`
qualified dealers and confirmations), never a key the ballot box or the community merely
reports: the ballot is sealed to that key whole, or encrypted option
by option with proofs that each is 0 or 1 and the question's count is one the manifest admits.
The proofs, or the seal's associated data, bind the cast's tag, so a copy of the ballot under
another ticket proves nothing (CONVENTIONS §9.3 – 9.4). The attestation is made over the
encrypted form, and the cleartext ballot never leaves the VTA.
`vta/pcs/vote` refuses such a manifest. The receipt is checked the same way.

## The trustee's round

A trustee of a sealed or tallied-encrypted election holds a transport key and a share of the
election key; any `threshold` of the trustees decrypt the result after close, and fewer cannot.
The VTA is the custodian of both, and signs each `voting/trustees/*` request as the trustee — a
persona it holds, named in the manifest's `trustees.dids`. The client carries the documents to
the ballot box (TSP or DIDComm; HTTPS where it has no session).

From step 2 on, every task is version 0.2 and takes `ceremony`: the trustees' signed steps, as
`voting/trustees/status` lists them in `steps`. **The VTA acts on those alone, each proof
verified against its trustee's DID** — never on a value the ballot box reports, because a box
that could choose the transport keys, the complaints, the dealings or the decryption targets
could collect the shares or decrypt a single voter's ballot (CONVENTIONS §9.6).

| Step | VTA task | Then, to the ballot box |
|---|---|---|
| 1 | `vta/pcs/trustee/enrol` — the transport key, made on first use from a fresh path under the context's base | `voting/trustees/enrol` |
| 2 | `vta/pcs/trustee/deal` — the polynomial's commitments and each trustee's share sealed to the transport key in that trustee's signed enrolment. The VTA pins the set it dealt to; a later deal against other keys is `ceremonyChanged` | `voting/trustees/deal` |
| 3 | `vta/pcs/trustee/keys` — each share dealt to this trustee in a signed dealing opened and checked; the dealers whose shares fail are the complaints | `voting/trustees/confirm` |
| 4 | `vta/pcs/trustee/justify`, with the manifest, only for a complaint in the complainant's own signed confirm (else `noComplaint`) — the share dealt to the complainant, in the clear | `voting/trustees/justify` |
| 5 | `vta/pcs/trustee/keys` again — the key formed from the steps, the trustee's share computed, checked against its verification key, and kept. A held share is never replaced (`keyMismatch`) | — |
| 6 | after close, `vta/pcs/trustee/decrypt` with the `targets` and the community's signed `authorization` of them (`voting/trustees/authorize`, a `decryptionAuthorized` entry) — one partial decryption per target, each with its proof. Refused without a valid authorization (`authorizationInvalid`), and once per election (`alreadyDecrypted`) | `voting/trustees/decrypt` |

Every step reads the ballot box first: `voting/election/show` for the manifest and
`voting/trustees/status` for where the ceremony stands. A private board answers those only to
the community, its auditors and its trustees, so the client has the VTA sign them as the trustee
with `vta/pcs/trustee/read` — which signs those two reads of one election and nothing else.

`pnm elections trustee step <election> --community <did> --ballot-box <did> --trustee <did>
--context <ctx>` runs the whole round from the command line. It reads both, takes every step the
ceremony needs of this trustee now, and carries each document to the ballot box's HTTPS door.
Run it again at any time, or pass `--watch` to repeat every 30 seconds until the result is out.
`pnm elections trustee status` shows where the ceremony stands. After close it waits for the
community to authorize the decryption before it decrypts anything.

**Why the community authorizes the targets.** The targets are what the trustees decrypt: the
totals of a tallied election, or each sealed ballot. Only someone who has checked the board can
say they are the right ones — every cast admitted before the close, each total the sum of the
casts. The community does that check (it computes the targets from the board it verified) and
signs their digest under the closing head. A trustee's VTA then decrypts that set and nothing
else, so a ballot box cannot present one voter's ciphertext as a "total" and read the vote.

The transport secret and the polynomial are re-derived from the trustee's path on every use,
domain-separated, so a repeated `deal` is the same dealing and `justify` reveals exactly the
share that was dealt. The key share is the sum of other trustees' shares and cannot be
re-derived; it is kept wrapped under the seed-derived KEK (`secret:trustee:…` in
`pcs_engine`). No task returns either. An MCP host confirms every `justify` and `decrypt`.

The ballot box puts each enrolment, dealing, confirmation and justification on the board as the
trustee's request exactly as received, proof included (a `trusteeStep` entry, conventions §9.6),
so the community and every auditor verify each step as this trustee's. That signature is what
stops a ballot box dealing in a trustee's name and holding the election key itself.

## Audit

Every task that changes state or produces an artefact is audited (`pcs.*`): the
caller, the context, and the community or application. **An applicant's PCS
identifier, a tag, and statement metadata are never recorded beside the vetter
that produced them** — that pairing is exactly what hidden vetting keeps from the
community, and an audit trail is read by more people than the engine.

## What it costs

The VTA can compute every tag of its user, so vetter anonymity holds against the
community, other members, applicants and the mediator, and **not** against the
vetter's own VTA. That is the trust the member already places in the VTA for their
persona keys and relationship graph. Hidden vetting therefore requires that a
vetter's VTA is not operated by the community's operator, or by anyone colluding
with it.

## Clients

- Rust: `VtaClient::pcs_*` (`vta_sdk::client`), taking and returning the generated
  `trust_tasks_rs::specs::vta::pcs` types.
- Mobile: `vta_mobile_core::pcs::{build_pcs_task, parse_pcs_response}` — one
  builder and one parser over a `PcsTask` enum; the payload is checked against its
  generated type before anything is signed.

## Not yet

- **Driving the trustee's round from the console or a wallet.** `pnm elections trustee step`
  drives it from the command line; other clients carry each step through
  `VtaClient::pcs_trustee_*`.
- **Withdrawal.** A vetter's withdrawal of one attestation (the tag and a proof of
  knowledge of its key) is an engine operation, and joins the family once the
  community-side task that accepts it is specified.
- **A VTA-driven drip.** Today the client carries each tick. The engine is the same
  one a VTA-scheduled drip would use; what that needs is the VTA sending the
  member-signed draw to the community itself.
