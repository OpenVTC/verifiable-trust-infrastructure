---
id: https://trusttasks.org/openvtc/vtc/spec/join-requests/manifest/1.0
title: VTC Join Requests — Manifest (discovery)
status: retired
supersededBy: https://trusttasks.org/spec/vtc/join-requests/manifest/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/trust-tasks
  - didcomm: https://trusttasks.org/openvtc/vtc/spec/join-requests/manifest/1.0
---

# VTC Join Requests — Manifest (discovery)

> **Trust Task document flow (current).** Manifest is now a `trust_tasks_rs`
> TrustTask document on the `/spec/…` URI, posted to `POST /v1/trust-tasks`
> (or sent as a DIDComm message of this `type`). It is a public read — the
> document carries no holder proof, only `recipient` (= the VTC DID) +
> `expiresAt`. Success → `#response` with `{communityDid, criteria}`. The
> former bespoke `GET /v1/join-requests/manifest` is superseded.

The `manifest` verb is the join ceremony's **pre-submit discovery** step
(protocol §2 verb set). A prospective applicant asks the VTC *what it
needs to present to join* — the community's evidence requirements — so
the applicant can assemble a presentation before opening a thread with
`request` (= `submit`) or answering a `present`.

`manifest` is a **read**: it opens no thread, mints no challenge, and
writes nothing. It is the public face of the community's registered
**Accepts criteria** (`schemas::accepts`) — each criterion is a named
DCQL **Presentation Definition** over registered credential types, plus
a human description.

## Authentication

Unauthenticated — manifest is public discovery (the "how do I join this
community" page). Rate-limited per the unauth bucket (`vtc-mvp.md` §9.6).
It returns only the community's *stated requirements*, never any
applicant or member data.

## Response

```jsonc
{
  "communityDid": "did:webvh:…",          // this VTC's DID (the would-be VMC issuer)
  "criteria": [
    {
      "id": "join-evidence",               // criterion id to cite on the present/query thread
      "description": "Present a witness credential from a recognised notary.",
      "presentationDefinition": { /* DCQL query */ }
    }
  ]
}
```

- `criteria` is the community's registered Accepts set
  (`schemas::accepts::list_accepts`). Each entry's
  `presentationDefinition` is the criterion's DCQL query; `id` is the
  value a holder cites when the VTC sends a `credential-exchange/query`
  for that criterion (see `present`).
- An empty `criteria` array means the community has registered no
  evidence requirement — joining is gated by the active `join.rego`
  alone (e.g. open-join or manual review), with no credential to
  pre-assemble.

> **Decided (review):** 1.0 returns **all** registered Accepts criteria;
> there is no per-criterion "purpose" tag yet, so manifest does not
> distinguish join criteria from those used by other ceremonies. A
> `purpose`/scope tag on `AcceptsCriterion` (so manifest can return only
> the join-relevant subset, and name a default) is a follow-up.

## Errors

- `429 Too Many Requests` — rate-limited (per-IP for REST,
  per-sender-DID for DIDComm).

Framework errors use the `trust-task-error` type, not a verdict
(protocol §3) — `manifest` runs no policy.

## Audit

None — `manifest` is a stateless public read.
