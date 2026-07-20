---
id: https://trusttasks.org/openvtc/vtc/policies/activate/1.0
title: VTC Policies — Activate
status: draft
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: POST /v1/policies/{id}/activate
---

# VTC Policies — Activate

Flips the per-purpose active pointer for a previously-uploaded
policy. Spec §7.1 + plan §D8. The flip is a single fjall put
serialised under a process-wide async mutex (see
`crate::routes::policies::admin::ACTIVATE_LOCK`) so concurrent
activations of the same purpose cannot interleave their audit
envelopes.

## Authentication

`AdminAuth` — bearer-token JWT with `role: Admin`.

## Request

```
POST /v1/policies/{id}/activate
```

Empty body. `{id}` is the UUID returned by `POST /v1/policies`.

## Response (`200 OK`)

```
{
  "id": "1a2b3c…",
  "purpose": "join",
  "sha256": "abcd…",
  "previousPolicyId": "0f1e…"   // null on the first activation
}
```

The audit envelope `PolicyActivated` records the same id +
purpose + sha256 and the predecessor id (omitted on first
activation per `serde(skip_serializing_if = "Option::is_none")`).

## Errors

- `401 Unauthorized` — missing / invalid session token.
- `403 Forbidden` — caller is not Admin.
- `404 Not Found` — no policy with this id.
- `409 Conflict` — this policy is already active for its
  purpose. The activate flow is idempotent at the **wire layer**
  (re-activating a different policy than the live one for the
  same purpose succeeds), but re-activating the *same* row twice
  is refused so the audit log doesn't carry no-op events.
- `500 Internal Server Error` — audit writer unavailable.

## Side-effects

1. Stamps `activated_at = now()` on the policy row.
2. Writes `active_policies:<purpose>` = id.
3. Emits `PolicyActivated` audit envelope.

The previous active row for the purpose remains in the
`policies:<uuid>` keyspace; it just stops being pointed at.
M2.4's `GET /v1/policies?status=archived` surfaces it.

## Notes

The compiled-policy in-memory registry (plan §D8) lands in M2.5
when default policies need to be evaluated by the join + removal
handlers. M2.3 alone flips the fjall pointer — there are no
consumers yet, so the swap is trivially atomic.
