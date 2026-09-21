# How an admitted member receives its credentials

When a join ends in admission, the community issues two credentials to the new
member:

- a **`MembershipCredential`** (the VMC), and
- a **role `EndorsementCredential`** (`endorsement.type = "CommunityRole"`), for
  the role admission granted.

It then **delivers each one as its own message**. A client that waits only for
the answer to its submit can miss them. This page covers what arrives, where,
and what a client has to handle. The last section is the migration note for
clients written against the earlier behaviour.

## What arrives

After an `allow` verdict (auto-admit), and after an admin approves a pending
request, the VTC sends the applicant **two DIDComm messages**, one per
credential (`vtc-service/src/credentials/delivery.rs`):

| | |
|---|---|
| DIDComm `type` | `https://trusttasks.org/spec/credential-exchange/issue/0.1` — the task URI itself, **not** the Trust Task binding envelope |
| Thread | A **new thread per credential**. An `issue` is a one-way deposit, not a reply to your submit |
| Body | An OID4VCI credential response, verbatim: `{ "credential_response": { "credential": { …the signed VC… } } }` |
| Order | **Not guaranteed.** The role endorsement can arrive before the membership credential |
| Sender / recipient | Authcrypt from the community DID to the **proven applicant**, never to a relayer |

Delivery goes through the VTC's durable outbox. The send is queued, then
retried until acknowledged, for up to 24 hours. So a client that is offline at
admission still receives the credentials when it reconnects, within that
window. The same path delivers a re-minted role endorsement after a role change
and a vetter role credential after a vetter grant.

Delivery needs the community to have messaging configured. A VTC without a
mediator issues the credentials but cannot push them. That failure is logged,
not returned: the member is admitted either way.

## What the verdict carries

The `#response` to `vtc/join-requests/submit/0.2` is a `VerdictResponse`. On
`allow` the current VTC also puts both credentials in it, as
`verdict.with.vmc` and `verdict.with.roleVec`, on every transport. The REST
admin decision (`POST /v1/join-requests/{id}/decide`) returns them as `vmc` and
`roleVec`, so an admin can hand them over out of band.

**Do not build a session client on those inline fields.** The contract, as
`vta_sdk::protocols::join_requests::VerdictWith` states it, is that the
credentials are returned inline over REST and **delivered in a follow-up
message over DIDComm, where the inline copy may be omitted**. Over a session,
the `credential-exchange/issue` messages are the delivery. The inline copy is a
REST convenience.

## What a client has to do

1. **Match the submit's answer by type.** The answer to your submit is the
   document whose `type` ends `#response` (or a `trust-task-error`) on your
   submit's thread. It is not "the next message to arrive".
2. **Keep an inbox for the rest of the session.** Accept
   `credential-exchange/issue/0.1` messages that are not replies to anything,
   read `credential_response.credential`, and store it. Expect two after an
   admission, in either order.
3. **Accept messages typed as the document.** Over DIDComm the VTC accepts a
   submit either in the binding envelope (`…/binding/didcomm/0.1/envelope`) or
   typed as the task. It sends its reply, and the `issue` deposits, typed as
   the document itself, not in the envelope. A client that only unwraps the
   envelope keeps nothing, and sees no error.
4. **Verify what you store.** Check the proof, check that the issuer is the
   community's DID, and check that the subject is you. A deposit is authcrypt
   from the community, but the credential is what you will later present.

A deposit still undelivered after 24 hours is abandoned. A vetter can ask for
its grant credential again with `vtc/vetting/vetters/resend/0.1`
([`vetting.md`](vetting.md) §3). There is no equivalent resend for the
membership credential and role endorsement yet, so a client should store them
as soon as they arrive.

## Migration note — Eucalyptus

**Who this is for:** a client written against the 0.28-era stack (vta-service
0.28, vta-sdk 0.38) that read the membership credential and role endorsement
from `verdict.with.vmc` / `verdict.with.roleVec` in the answer to its submit.

**What changes for you:** on the Eucalyptus train (`VTI-Eucalyptus-RC-0` and
later), treat the submit's `allow` as the **decision** and nothing more. The
credentials arrive separately, as two `credential-exchange/issue/0.1` deposits
on threads of their own, in either order, typed as the task rather than in the
binding envelope. A client that waits only for the reply to its submit, or
that unwraps only the binding envelope, ends the join with no credentials and
no error.

**Why:** delivery is the only channel that reaches a holder that is not waiting
on the reply: one that submitted and went offline, or one admitted later by an
admin decision. It is also retried until acknowledged, where a reply is sent
once. The deposits are what every admission path uses, so a client that
handles them handles all of them, and a client that reads the verdict handles
only one.

**What to change:**

- Match the answer to your submit by its `#response` type (above), not by
  arrival order.
- Keep an inbox open on the community session after submit, and store the
  `credential-exchange/issue/0.1` deposits as they arrive.
- If you still read `verdict.with.vmc` / `roleVec`, treat them as optional.
  When they are present they are the same credentials the deposits carry, so
  store by credential `id` to avoid duplicates.

**What does not change:** the REST admin decision still returns both
credentials inline, and the verdict's `effect`, `role` and `requestId` are
unchanged.

## See also

- [Credentials](credentials.md) — VMC / VEC details and status lists.
- [Community lifecycle](community-lifecycle.md) — the join flow.
- [Bootstrap runbook](bootstrap-runbook.md) — admitting a community's first
  members.
