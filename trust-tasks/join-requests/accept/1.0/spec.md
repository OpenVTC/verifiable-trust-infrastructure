---
id: https://trusttasks.org/openvtc/vtc/spec/join-requests/accept/1.0
title: VTC Join Requests — Accept (reciprocal VMC)
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/trust-tasks
  - didcomm: https://trusttasks.org/openvtc/vtc/spec/join-requests/accept/1.0
---

# VTC Join Requests — Accept (reciprocal VMC)

> **Trust Task document flow (current).** Accept is now a `trust_tasks_rs`
> TrustTask document on the `/spec/…` URI, posted to `POST /v1/trust-tasks`
> (or sent as a DIDComm message of this `type`). Payload `{requestId, vmcId,
> vc}`; the member is the document `issuer` (REST proof / DIDComm authcrypt
> sender). Success → `#response` receipt; failures → `trust-task-error`. The
> bespoke `memberDid`/`signature` body fields are superseded.

The `accept` verb closes the join ceremony's **reciprocal step**: the
newly-admitted member counter-signs the membership the VTC issued,
forming the **bidirectional DTG membership edge**. It discharges the
`reciprocate_vmc` obligation that the join `allow` carried (ceremony
catalog §2; protocol §2 verb set; pipeline §11).

A join `allow` issues the community → member half of the edge: the VTC
mints the VMC + role VEC and (best-effort) delivers them to the
applicant. That half alone is **one-directional** — the community
asserts "this DID is a member," but the member has not yet asserted
"I am a member of this community." `accept` carries the member's
counter-assertion (the *reciprocal VMC*) back to the VTC, which records
it and completes the edge.

```
… join-requests/request|present → allow {role, obligations:["reciprocate_vmc"]}
   VTC issues VMC + role VEC to the member (community → member half)
member ─join-requests/accept {reciprocal VMC, thread}─▶ VTC
   VTC verifies + records the reciprocal edge (member → community half)
```

## Relationship to the existing flow

- The `request` verb is the existing `join-requests/submit/1.0`
  (protocol §4). `accept` carries the **same `thread_id`** the join
  request minted, plus the `vmcId` of the VMC it reciprocates.
- `accept` is valid only against a request whose membership has been
  **issued** — i.e. the join verdict was `allow` (auto-admit on submit/
  present) or an admin `approve` ran. It is rejected for a request in
  `Pending`/`Deferred`/`Rejected` (no VMC to reciprocate) and is
  idempotent once the edge is recorded (see Errors).

## The reciprocal artifact

The member's counter-assertion is a **member-issued Verifiable
Credential** — the *reciprocal VMC* (`MembershipAcknowledgement`). The
member is the issuer; the credential subject is the **community** (this
VTC — the DID that issued the VMC) and asserts the member accepts
membership under the issued `vmcId`. Concrete 1.0 shape:

```jsonc
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential", "MembershipAcknowledgement"],
  "id": "urn:uuid:…",                  // recorded as the member's reciprocalVcId
  "issuer": "did:key:z…member",        // MUST equal memberDid
  "credentialSubject": {
    "id": "did:webvh:…community",       // MUST equal this VTC's DID (the VMC issuer)
    "reciprocates": "urn:uuid:…vmc"     // MUST equal the member's current VMC id
  },
  "proof": { "type": "DataIntegrityProof", "cryptosuite": "eddsa-jcs-2022",
             "proofPurpose": "assertionMethod", "verificationMethod": "did:key:z…member#…" }
}
```

The `eddsa-jcs-2022` issuer proof IS the counter-signature: for a
`did:key` member (Phase 1) the VTC verifies it directly against the
member's `did:key` (no resolver), binding `verificationMethod` to
`memberDid`. Using a VC (not a bespoke signed struct) follows the
workspace rule that holder → VTC authorization assertions are VC/VP. The
VTC records the VC's `id` on the Member row and emits the audit edge
event.

> **Decided:** the reciprocal artifact is the **VC/VP** form (per the
> house rule that holder → VTC assertions are VPs), giving a standalone,
> independently-verifiable member-side credential for the DTG edge. The
> lighter alternative — a detached Ed25519 signature over `vmcId`,
> mirroring the `submit` holder binding — was considered and rejected
> because it produces only a binding proof, not a member-side credential.

## Authentication

Unauthenticated trigger; the reciprocal VP / DIDComm envelope **is** the
auth, identically to `submit`:

### DIDComm (preferred)

`memberDid` comes from the DIDComm `from` field (the authcrypt sender) —
no separate signature in the body; the envelope binds the member. The
body carries `requestId` (no URL path over DIDComm), `vmcId`, and the
reciprocal `vc`. The handler replies with an `accept-receipt/1.0`
message (`requestId` + `status` + `reciprocalVcId`), threaded (`thid`)
on the accept message id.

### REST holder binding (fallback)

Request body carries `memberDid`, the reciprocal `vc`, and a
hex-encoded Ed25519 signature over the domain-tagged
(`vtc-join-accept/v1\0`) canonical JSON of the body minus `signature` —
the same construction `submit` uses. `did:key` members only in 1.0
(`did:webvh` resolution is a follow-up, as on `submit`).

## Effects

On a verified, in-state accept:

1. Verify the reciprocal VP/VC holder proof binds `memberDid`, and that
   `memberDid` matches the request's `applicantDid` and the VMC subject.
2. Resolve the VMC referenced by `vmcId` against the member's current
   `current_vmc_id`; reject a mismatch.
3. Record the bidirectional edge: stamp the Member row with the
   reciprocal VC id and an `acceptedAt` timestamp, marking the
   `reciprocate_vmc` obligation discharged.
4. Audit `MembershipReciprocated { requestId, memberDid, vmcId,
   reciprocalVcId }` (new audit event — `vti-common::audit`).

> **Decided:** membership (ACL + VMC) is **effective at admit**, before
> `accept`. The edge is *pending reciprocation* until accept, with **no
> functional restriction** on the member in the interim; an optional
> reciprocation deadline is left to policy (not enforced by the host in
> 1.0). The stricter alternatives — auto-revoke on a deadline, or gating
> member capabilities until the edge is bidirectional — were considered
> and deferred.

## Errors

- `400 Bad Request` — malformed VP / signature / non-`did:key` member,
  or `memberDid` ≠ the request's applicant / VMC subject.
- `404 Not Found` — request id unknown.
- `409 Conflict` — request has no issued membership to reciprocate
  (status is `Pending`/`Deferred`/`Rejected`), **or** `vmcId` does not
  match the member's current VMC.
- `429 Too Many Requests` — rate-limited (per-IP for REST,
  per-sender-DID for DIDComm), same bucket as `submit`.

Framework errors use the `trust-task-error` type, not a `deny` verdict
(protocol §3): `accept` records an edge, it does not run the policy.

## Idempotency

A second `accept` that matches an already-recorded edge (same
`memberDid` + `vmcId` + reciprocal VC) returns `200 OK` with
`status: "accepted"` and does **not** re-stamp or re-audit. A
*different* reciprocal VC for an already-reciprocated VMC is a `409`.

## Audit

`MembershipReciprocated { requestId, memberDid, vmcId, reciprocalVcId }`
— correlatable with the `JoinRequestApproved` / `VmcIssued` events from
the same `requestId`.
