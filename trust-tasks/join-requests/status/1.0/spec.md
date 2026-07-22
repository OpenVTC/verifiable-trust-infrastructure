---
id: https://trusttasks.org/openvtc/vtc/spec/join-requests/status/1.0
title: VTC Join Requests — Status (applicant poll)
status: retired
supersededBy: https://trusttasks.org/spec/vtc/join-requests/status/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/trust-tasks
  - didcomm: https://trusttasks.org/openvtc/vtc/spec/join-requests/status/1.0
---

# VTC Join Requests — Status (applicant poll)

> **Trust Task document flow (current).** Status is now a `trust_tasks_rs`
> TrustTask document on the `/spec/…` URI, posted to `POST /v1/trust-tasks`
> (or sent as a DIDComm message of this `type`). Payload `{requestId}`; the
> applicant is the document `issuer` (REST proof / DIDComm authcrypt sender).
> Success → `#response` with `{requestId, status, needs?, presentationDefinition?}`;
> an unknown request → `trust-task-error` `taskFailed`. The bespoke
> `applicantDid`/`signature` body fields are superseded.

The `status` verb lets an **applicant poll their own join request**
while it is in flight (protocol §2 verb set: "poll a thread in
`Pending`/`Deferred`"). It is the applicant-facing counterpart to the
admin-only `show` (`GET /v1/join-requests/{id}`, `AdminAuth`): same
underlying row, but `status` is authenticated by the *applicant's holder
binding*, returns only non-sensitive lifecycle fields, and never exposes
the stored VP or moderator notes.

It is the universal fallback for the async paths: after a `refer`
(→ `Pending`, awaiting an admin `approve`/`reject`) or a `request_more`
(→ `Deferred`, awaiting more evidence over `present`), a DIDComm-reachable
applicant may be pushed the outcome, but `status` is always available to
poll.

## Authentication

Holder-bound to the request's `applicantDid`, identically to `submit` /
`accept` — the request is not public, so a leaked/guessed `requestId`
alone must not reveal its state.

### DIDComm (preferred)

`applicantDid` is the DIDComm `from` field (authcrypt sender). The body
carries `requestId` (no URL path over DIDComm). The handler rejects a
sender that is not the request's applicant.

### REST holder binding

`POST /v1/join-requests/{id}/status` — a POST (not GET) because the read
is holder-authenticated. Body carries `applicantDid` and a hex-encoded
Ed25519 `signature` over the domain-tagged (`vtc-join-status/v1\0`)
canonical JSON `{ applicantDid, requestId }`. `did:key` applicants only
in 1.0 (as on `submit`). The signer must match the request's applicant.

> **Decided (review):** `status` is holder-authenticated (not an
> unauthenticated capability-URL keyed by the unguessable `requestId`).
> The family is uniformly holder-bound; a poll that leaks lifecycle state
> on a guessed/shared id is avoided. The cost is a POST-for-read on the
> REST path.

## Response

```jsonc
{
  "requestId": "urn:uuid:…",
  "status": "pending" | "deferred" | "approved" | "rejected" | "withdrawn",
  // present only when status == "deferred" (a request_more verdict):
  "needs": ["agreed:code-of-conduct"],
  "presentationDefinition": { /* DCQL — what to present next over `present` */ }
}
```

- `needs` + `presentationDefinition` are projected from the request's
  stored `policy_decision` (the `request_more` verdict
  `realize_join_verdict` persisted). Absent for every other status.
- `approved` does **not** re-deliver credentials — the VMC + role VEC
  were delivered at admit (and returned inline on a REST auto-admit).
  `status` reports the disposition only.

## Errors

- `400 Bad Request` — malformed / non-`did:key` applicant; signer ≠ the
  request's applicant.
- `404 Not Found` — request id unknown.
- `429 Too Many Requests` — rate-limited.

Framework errors use the `trust-task-error` type (protocol §3) —
`status` runs no policy.

## Audit

None — a holder reading their own request's lifecycle is not an
audit-significant state change.
