# Join criteria

A community's **join criteria** are its rules for who may join and how. Each
criterion is one way in. It states:

- an **admission** mode — `automatic` (a submission that meets it is admitted
  without a person deciding) or `review` (it is referred to an administrator,
  who decides);
- the **requirements** a submission must meet, any of them or none:
  - **credentials** — a DCQL query, and whose credentials count
    (`credentialIssuers`): `community` (this community's own), `recognised`
    (this community's, or a community it recognises through the trust
    registry) or `any` (any issuer whose credential verifies);
  - **an invitation** (`invitationRequired`) — a valid, unconsumed invitation
    this community issued to the applicant;
  - **peer vetting** (`vetting`) — statements from the community's vetters,
    counted as [Peer identity vetting](vetting.md) describes.

Which criteria a community publishes is its administrators' decision. Nothing
in the specification or the service assumes one: open admission, admission
only after review, admission only by invitation, and any combination are all
expressed the same way. Specification:
[`vtc/join-requests/manifest/0.3`](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/specs/vtc/join-requests/manifest/0.3/spec.md),
[`vtc/join-requests/submit/0.3`](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/specs/vtc/join-requests/submit/0.3/spec.md)
and
[`vtc/schemas/accepts/register/0.2`](https://github.com/trustoverip/dtgwg-trust-tasks-tf/blob/main/specs/vtc/schemas/accepts/register/0.2/spec.md).

## How a submission is decided

1. **Which criterion governs.** A submission may name the criterion it applies
   under, by the `requirementsDigest` the manifest published (`criterion` on
   `vtc/join-requests/submit/0.3`). When it names none, it is decided under the
   **first criterion it meets, in the order the community lists them** — and
   when it meets none, the first listed. So where several criteria are met, the
   order decides which one governs: an automatic criterion listed before a
   review one admits; the other way round, the review criterion refers.
2. **Whether it meets it** — every requirement the criterion states, and only
   those. A credential that does not verify (signature, validity window,
   revocation), or is not the applicant's own, meets nothing. Something
   presented that the criterion does not ask for — an invitation, a credential
   — does not help meet it.
3. **What follows**, enforced by the service whatever the join policy says:
   - not met → never admitted, and never referred (a referral is how an
     administrator admits). The applicant is asked for what is missing
     (`requestMore`, `needs` naming it), or the policy refuses;
   - met, `review` → referred to an administrator. Meeting a review criterion
     never admits by itself;
   - met, `automatic` → admitted, unless the join policy refuses or refers it
     on grounds of its own (an excluded applicant, say). A policy can tighten a
     decision, never loosen it.

A community with **no** criteria accepts no applications: a submission is
refused with `submit:notAccepting`. A submission naming a digest the community
does not publish is refused with `submit:criterionUnknown`.

The decision records which criterion, and which version of it, governed.

## The defaults

A new community starts with three criteria, in this order:

| # | id | admission | requires |
|---|---|---|---|
| 1 | `invited` | automatic | an invitation this community issued |
| 2 | `member-credential` | automatic | a `MembershipCredential` from this community, or (with a trust registry configured) one it recognises |
| 3 | `review` | review | nothing |

So an invited applicant, or a member of a recognised community, is admitted
straight away, and everyone else is reviewed. These are a starting point, not
rules — change them like any other criterion:

- **Review everyone**: remove `invited` and `member-credential`. Invitations
  and credentials then admit nobody; `review` refers every application.
- **Admit everyone**: replace `review` with a criterion that requires nothing
  and admits automatically.
- **Invitation only**: remove `member-credential` and `review`.
- **Vetted members**: add a criterion with a `vetting` object, `automatic` or
  `review` as the community wants.

The defaults are offered once. A community whose administrators remove every
criterion is left with none — not accepting applications — and is not handed
the defaults again.

## Order

The order is registration order: a new criterion goes last, and replacing one
keeps its place. To move a criterion, remove it and register it again. The
join manifest lists criteria in this order, and the console's **Vetting →
Requirements** page shows it.

Put a criterion that requires nothing **last**: listed first, it is met by
every submission, so it would govern every application that names no
criterion.

## Versions

Each criterion's `requirementsDigest` covers everything about it — admission
included — so any change to a criterion changes its digest. The one exception
is how hidden vetting runs: its drip rate, tick length, live vetter and token
labels and events are left out, so republishing them does not void the
attestations applicants already hold. Its suite and keys are covered. An applicant who
cited an earlier digest is decided under that earlier version while its
`vetting.requirementsGrace` lasts, measured from when it was replaced or
removed; without a declared grace, the current version governs. A supplement
(`vtc/join-requests/supplement/0.1`) re-decides a request under the criterion
it was first decided under.

## Managing criteria

In the console: **Vetting → Requirements**. As signed documents:

| Task | |
|---|---|
| `vtc/schemas/accepts/register/0.2` | add, or replace by id |
| `vtc/schemas/accepts/list/0.2` | every criterion, in id order |
| `vtc/schemas/accepts/show/0.2` | one by id |
| `vtc/schemas/accepts/delete/0.1` | remove one |

Registration refuses a criterion the community could not decide against:
`credentialIssuers: recognised` without a trust registry configured is
`unsupportedRequirement`. A criterion with a query must say whose credentials
count, and one without a query must not.

## The join policy

The default `join.rego` follows the criterion: admit under a met automatic
criterion, refer under a met review criterion, ask for what an unmet criterion
lacks. An operator replaces it only to tighten — the service holds every
verdict to the governing criterion, so no policy admits a submission that does
not meet its criterion, and none admits on a review criterion.
