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

Neither is `sign`, and `sign` confers neither (VTI-VTA-007). `application`
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

- **Withdrawal.** A vetter's withdrawal of one attestation (the tag and a proof of
  knowledge of its key) is an engine operation, and joins the family once the
  community-side task that accepts it is specified.
- **A VTA-driven drip.** Today the client carries each tick. The engine is the same
  one a VTA-scheduled drip would use; what that needs is the VTA sending the
  member-signed draw to the community itself.
