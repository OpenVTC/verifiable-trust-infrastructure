---
id: https://trusttasks.org/spec/credential-exchange/query/1.0
title: Credential Exchange — Query
status: Draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - didcomm: https://trusttasks.org/spec/credential-exchange/query/1.0
---

# Credential Exchange — Query

`verifier → holder`. The verifier asks the holder to present a
credential. The body is an **OID4VP DCQL query** + a freshness
`nonce` + a **mandatory `purpose`** shown to the holder.

## Body

`{ dcql_query, nonce, purpose }`:

- `dcql_query` — the DCQL query. Per-credential `format` selector
  (`dc+sd-jwt`, `ldp_vc`, …), `meta` type discriminator
  (`vct_values` for SD-JWT-VC, `type_values` for W3C), and `claims`
  paths.
- `nonce` — verifier freshness, bound into the presentation.
- `purpose` — **mandatory, never optional**, and shown to the holder.
  Purpose binding: a verifier cannot ask for a credential without
  stating why.

## Privacy — no wallet enumeration

The holder gathers candidates **only** via the type index named by
the query's `meta` discriminator — there is no enumeration primitive.
A query carrying no `vct_values` / `type_values` contributes no
candidates, so the holder never blind-scans its whole wallet to
answer a query.

## Consent

A matched query is gated by the holder's consent policy. A **trusted**
verifier is auto-consented and the holder replies immediately with
[`present/1.0`](../../present/1.0); any other verifier **defers** —
the query is persisted for an out-of-band approval, and the verifier
is told consent is required. Approval mints a query-scoped consent
record and re-presents on-thread.

## Authentication

DIDComm authcrypt authenticates the **verifier** (the `from` DID).
The holder presents its **own** held credentials with its own
authority; the consent policy is the gate.
