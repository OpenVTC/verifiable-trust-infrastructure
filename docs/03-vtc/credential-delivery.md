# How an admitted member receives its credentials

When a join ends in admission, the community issues two credentials to the new
member:

- a **`MembershipCredential`** (the VMC), and
- a **role `AuthorityCredential`** (a VAC whose `credentialSubject.authority` is
  `{ scope: <community DID>, actions: ["role:<role>"], maxAttenuation: 0 }`),
  for the role admission granted.

Both are DTG credentials under the v1 context, issued by the community with
`issuerScope` `public`.

It then **delivers each one as its own Trust Task**. A client that waits only
for the answer to its submit can miss them. This page covers what arrives, where,
and what a client has to handle. The last section is the migration note for
clients written against the earlier behaviour.

## What arrives

After an `allow` verdict (auto-admit), and after an admin approves a pending
request, the VTC pushes the applicant **two `credential-exchange/issue/0.1`
Trust Task documents**, one per credential
(`vtc-service/src/credentials/delivery.rs`):

| | |
|---|---|
| Document `type` | `https://trusttasks.org/spec/credential-exchange/issue/0.1` |
| Carriage | Whichever transport you speak, **TSP > DIDComm > REST**, by the service types your DID document advertises (and TSP when you have recently spoken TSP to the community). Over DIDComm, in the binding envelope; over TSP, in the `{type, document}` binding |
| Proof | Signed by the community's operational key, `proofPurpose: authentication`, `issuer` = the community DID |
| Thread | No `threadId`: an unprompted `issue` answers nothing and starts its own thread |
| Payload | An OID4VCI credential response, verbatim: `{ "credential_response": { "credential": { …the signed VC… } } }` |
| Order | **Not guaranteed.** The role endorsement can arrive before the membership credential |
| Recipient | The **proven applicant**, never a relayer |

Delivery goes through the VTC's durable push engine. The push is queued, then
escalated to the next transport you offer if an attempt yields no evidence of
collection, for up to 24 hours. So a client that is offline at admission still
receives the credentials when it reconnects, within that window. The same path
delivers a re-minted role endorsement after a role change and a vetter role
credential after a vetter grant.

Delivery needs the community to have messaging configured. A VTC without a
mediator issues the credentials but cannot push them. That failure is logged,
not returned: the member is admitted either way.

## What the verdict carries

The `#response` to `vtc/join-requests/submit/0.2` is a `VerdictResponse`. On
`allow` the current VTC also puts both credentials in it, as
`verdict.with.vmc` and `verdict.with.roleVac`, on every transport. The REST
admin decision (`POST /v1/join-requests/{id}/decide`) returns them as `vmc` and
`roleVac` (vtc/join-requests/decide/0.1), so an admin can hand them over out of
band. Both members were named `roleVec` before role credentials became VACs;
a client reading the old name finds nothing.

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
3. **Send and receive in the envelope.** Over DIDComm the VTC accepts a Trust
   Task **only** in the binding envelope
   (`https://trusttasks.org/binding/didcomm/0.1/envelope`, the document as the
   message body) — `bindings/didcomm/0.2` §2–§4. A task whose DIDComm `type` is
   the task URI itself is refused with a DIDComm problem-report that names the
   envelope type, and never reaches the dispatcher. The `issue` deposits
   arrive the same way: open the envelope and read the document's own `type`.
4. **Verify what you store.** Check the document's proof and that its
   `issuer` is the community's DID; then check the credential's own proof,
   that its issuer is the community, and that its subject is you. The document
   proof attributes the delivery; the credential is what you will later
   present.

A deposit still undelivered after 24 hours is abandoned. A vetter can ask for
its grant credential again with `vtc/vetting/vetters/resend/0.1`
([`vetting.md`](vetting.md) §3). There is no equivalent resend for the
membership credential and role endorsement yet, so a client should store them
as soon as they arrive.

## Migration note — Eucalyptus

**Who this is for:** a client written against the 0.28-era stack (vta-service
0.28, vta-sdk 0.38) that read the membership and role credentials
from `verdict.with.vmc` / `verdict.with.roleVac` in the answer to its submit.

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
- If you still read `verdict.with.vmc` / `roleVac`, treat them as optional.
  When they are present they are the same credentials the deposits carry, so
  store by credential `id` to avoid duplicates.

**What does not change:** the REST admin decision still returns both
credentials inline, and the verdict's `effect`, `role` and `requestId` are
unchanged.

## Migration note — every credential-exchange step is a Trust Task

**Who this is for:** a client that received the `issue` deposits, the
invitation `offer`, the join `query`, the reciprocal-VMC request
(`vtc/members/request-vmc`) or the `join-requests/submit-receipt` as bare
DIDComm messages typed as their task URI, or that sent `credential-exchange/
request` or `present` that way.

**What changes for you:** each of those is now a signed Trust Task document.
The VTC **pushes** the ones it originates through the push engine (above), and
**serves** `request` and `present` on its Trust Task dispatcher, reachable
over TSP, DIDComm (in the binding envelope) and HTTPS alike. A `request` or
`present` typed as itself is refused, naming the envelope. None of the steps
defines a response document: what comes back on the transport is at most the
empty `#response` acknowledgement (SPEC §4.4.2), which you must not rely on.
The real answer is the next step, pushed to you on the same thread — `issue`
after your `request` (threaded on the offer), `join-requests/submit-receipt`
after your `present` (threaded on the query).

**Why:** a bare message typed as its task URI is exactly the carriage
`bindings/didcomm/0.2` §2 requires a consumer to refuse. It skipped every
document check the dispatcher applies — proof, freshness, recipient, replay —
and no transport but DIDComm could carry it at all.

**What to change:** unwrap the envelope (or the TSP binding) before routing on
type; verify the document proof; send `request` and `present` as signed
documents carrying the step's `threadId`; and wait for the next step, not for a
reply.

## See also

- [Credentials](credentials.md) — VMC / role VAC details and status lists.
- [Community lifecycle](community-lifecycle.md) — the join flow.
- [Bootstrap runbook](bootstrap-runbook.md) — admitting a community's first
  members.
