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

The drip is unconditional by design: a vetter draws on its schedule whether or not
it has vetted anyone, because a draw that tracked activity would report activity.

The first `root-request` for a context and community creates the vetter engine and
records the member DID. The engine keeps **one key for its whole life** — a vetter
with two keys would count as two vetters in one proof — and a later `root-request`
naming another member DID is refused `memberMismatch`.

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
| `pcs-vetter` (`pcsVetter`) | `root-request`, `root-accept`, `tokens/*`, `attest`, `vetter/show` | `admin`, `initiator` |
| `pcs-applicant` (`pcsApplicant`) | `applications/*`, `verify-attestation`, `prove` | `admin`, `initiator` |
| `pcs-voter` (`pcsVoter`) | `voter/register`, `voter/read`, `voter/accept`, `vote`, `vote-encrypted`, `voter/receipt` | `admin`, `initiator` |
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
| 0 | client → VTA → community | `vta/pcs/voter/read` — `vtc/elections/list` or `show` signed as the member (a persona this VTA holds), sent to the community unchanged: the manifest, parameters and disclosure the next steps need. The VTA signs only those two reads |
| 1 | client → VTA | `vta/pcs/voter/register` — a fresh key for this election and the blinded ticket request; a repeat before the ticket is held answers with the same request. With `member` (a persona this VTA holds), also `ticketDocument`: the request to the community already signed as that member, kept and returned unchanged on a repeat |
| 2 | client → community | `vtc/elections/tickets/issue` — `ticketDocument` as it came (or the request signed by a member DID the client holds); the community signs the ticket blind, one per eligible member |
| 3 | client → VTA | `vta/pcs/voter/accept` — unblinded and kept wrapped |
| 4 | client → VTA | `vta/pcs/vote` — the ballot checked against the manifest, the cast built, and the `voting/ballot/cast` document returned **signed by a key made for that cast alone** and never kept |
| 5 | client → ballot box | the cast document, from the client's own connection, after a pause; resent unchanged if the answer is lost |
| 6 | client → VTA | `vta/pcs/voter/receipt` — the ballot box's signed receipt kept, and checked for inclusion in a head the community kept |

A voter key is per election, so a key recovered later links one election, never a
member's voting history. The cast never carries the member's DID (VTI-VOT-003), and
audit names the election, never a tag, a cast or a receipt (VTI-VOT-100). An MCP
host confirms every `vote` (`vta-mcp`'s guard counts it destructive).

In a **sealed** or **tallied-encrypted** election (VTI-VOT-060 – 064, conventions §9) step 4
is `vta/pcs/vote-encrypted`, given the election key `vtc/elections/show` carries — the key the
community formed itself from the trustees' signed steps on the board, never one the ballot box
merely reports: the ballot is sealed to that key whole, or encrypted option
by option with proofs that each is 0 or 1 and the question's count is one the manifest admits.
The attestation is made over the encrypted form, and the cleartext ballot never leaves the VTA.
`vta/pcs/vote` refuses such a manifest. The receipt is checked the same way.

## The trustee's round

A trustee of a sealed or tallied-encrypted election holds a transport key and a share of the
election key; any `threshold` of the trustees decrypt the result after close, and fewer cannot.
The VTA is the custodian of both, and signs each `voting/trustees/*` request as the trustee — a
persona it holds, named in the manifest's `trustees.dids`. The client carries the documents to
the ballot box (TSP or DIDComm; HTTPS where it has no session):

| Step | VTA task | Then, to the ballot box |
|---|---|---|
| 1 | `vta/pcs/trustee/enrol` — the transport key, made on first use from a fresh path under the context's base | `voting/trustees/enrol` |
| 2 | `vta/pcs/trustee/deal`, with every trustee's transport key — the polynomial's commitments and each trustee's share sealed to its transport key | `voting/trustees/deal` |
| 3 | `vta/pcs/trustee/keys`, with every dealing — each share dealt to this trustee opened and checked; the dealers whose shares fail are the complaints | `voting/trustees/confirm` |
| 4 | `vta/pcs/trustee/justify`, if complained of — the share dealt to the complainant, in the clear | `voting/trustees/justify` |
| 5 | `vta/pcs/trustee/keys` again, with the formed `electionKey` — the trustee's share computed, checked against its published verification key, and kept | — |
| 6 | after close, `vta/pcs/trustee/decrypt` with the targets `status` lists — one partial decryption per target, each with its proof. Refused before `closedAt` (VTI-VOT-063) | `voting/trustees/decrypt` |

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

- **Driving the trustee's round** from a CLI or the console. The tasks and the SDK methods
  (`VtaClient::pcs_trustee_*`) are there; a client still has to carry each step.
- **Withdrawal.** A vetter's withdrawal of one attestation (the tag and a proof of
  knowledge of its key) is an engine operation, and joins the family once the
  community-side task that accepts it is specified.
- **A VTA-driven drip.** Today the client carries each tick. The engine is the same
  one a VTA-scheduled drip would use; what that needs is the VTA sending the
  member-signed draw to the community itself.
