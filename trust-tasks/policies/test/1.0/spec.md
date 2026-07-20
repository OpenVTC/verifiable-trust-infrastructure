---
id: https://trusttasks.org/openvtc/vtc/policies/test/1.0
title: VTC Policies — Test
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/policies/{id}/test
---

# VTC Policies — Test

Dry-runs a stored policy against a caller-supplied `input`. Does
**not** affect the active pointer, does not write to fjall, does
not emit audit envelopes beyond the operator-visible info log
line. Used to validate a candidate upload before activating.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Request

```
POST /v1/policies/{id}/test
Content-Type: application/json

{
  "query": "data.vtc.join.allow",
  "input": { "applicant": { "did": "did:key:zX", "vp_claims": { } } }
}
```

- `query` (required) — Rego query to evaluate. Caller picks the
  query so `test` can probe any rule in the module, not just
  `allow`.
- `input` (required) — JSON document fed to the policy as
  `input`. Shape is policy-specific; M2.6 / M2.7 will lock in
  the canonical shapes the daemon passes for `join.rego` /
  `removal.rego`.

## Response (`200 OK`)

```
{
  "id": "1a2b3c…",
  "purpose": "join",
  "sha256": "abcd…",
  "result": { "result": [ { "expressions": [ … ] } ] }
}
```

`result` is the raw regorus `QueryResults` JSON (`opa eval`-
compatible shape). Plucking `result[0].expressions[0].value`
yields the rule's output. For boolean rules, that value is
`true` / `false`. For object rules, it's the rule's body.

## Errors

- `400 Bad Request` — malformed JSON, missing `query` /
  `input`, or query syntax error.
- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — no policy with this id.
- `500 Internal Server Error` — regorus evaluation failure.

## Notes

- The policy is **recompiled per call**. The harness is cheap
  (regorus stores compiled modules behind an `Arc` so re-running
  the parser is the dominant cost, not codegen). Recompiling
  means `test` doesn't depend on a long-lived compiled-cache —
  archived (non-active) rows aren't cached in M2.5+.
- The endpoint never mutates state beyond log lines. Audit
  envelopes are reserved for `PolicyUploaded` / `PolicyActivated`
  — operators run `test` repeatedly and noisy audit would
  swamp real signal.
