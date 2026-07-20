---
id: https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0
title: VTC Join Requests — Submit (the ceremony `request` verb)
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/trust-tasks
  - didcomm: https://trusttasks.org/openvtc/vtc/spec/join-requests/submit/1.0
---

# VTC Join Requests — Submit

> **Trust Task document flow (current).** Submit is now a framework
> `trust_tasks_rs::TrustTask` **document** (the `/spec/…` URI). The request is
> a TrustTask document whose `payload` is `{vp, registryConsent, extensions}`;
> the success reply is a `#response` document carrying a **Verdict**
> (`{requestId, verdict:{effect, with}}` — effect `allow`/`refer`/`request_more`/
> `deny`); failures (invalid VIC, expired, malformed, duplicate) are framework
> **`trust-task-error`** documents (e.g. `permissionDenied` for an invalid VIC),
> never DIDComm problem-reports and never a `deny` verdict. Over REST the
> holder is authenticated by the document's `eddsa-jcs-2022` proof; over DIDComm
> by the authcrypt sender. Replay binding is the document `recipient` (= the VTC
> DID) + `expiresAt`. The bespoke `applicantDid`/`audience`/`created`/`signature`
> body fields below are superseded.

Persist a `JoinRequest` in status `Pending`. Phase 1 manual-
approval flow: admin / moderator runs approve or reject later.

## Authentication

Unauthenticated. The TrustTask document proof (REST) / authcrypt envelope
(DIDComm) is the auth — see spec §5.5.

### Holder binding (superseded — historical)

The original bespoke binding carried `applicantDid`, `vp`, optional
`registryConsent` + `extensions`, and a hex-encoded Ed25519 signature over the
canonical body prefixed with the domain tag `vtc-join-request/v1\0`. This is
replaced by the TrustTask document `proof` (see banner above).

### DIDComm

`applicantDid` comes from the DIDComm `from` field (the
authcrypt sender). No separate signature in the body — the
envelope IS the binding. The handler replies with a
`join-requests/submit-receipt/1.0` message carrying the
`requestId` + `status`.

## Errors

- `400 Bad Request` — malformed VP / signature / non-did:key
  applicant.
- `429 Too Many Requests` — rate-limited (per-IP for REST,
  per-sender-DID for DIDComm).

## Audit

`JoinRequestSubmitted { requestId, transport: "rest"|"didcomm" }`.
