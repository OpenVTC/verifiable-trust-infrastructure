---
id: https://trusttasks.org/openvtc/vtc/members/self-remove/1.0
title: VTC Members — Self-Remove
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/self-remove/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: DELETE /v1/members/me
  - didcomm: https://trusttasks.org/openvtc/vtc/members/self-remove/1.0
---

# VTC Members — Self-Remove

Spec §10.2. A member departs the community. The caller's DID
is the only target.

## Authentication

REST: any authenticated session (the caller IS the target).
DIDComm: the message's `from` field — authcrypt sender — IS the
target DID.

## Body

```text
{
  "disposition": ? "purge" | "tombstone" | "historical" | "policydefault"
}
```

Empty body is accepted; defaults to the Member's stored
`departure_preference`, falling back to
`PolicyDefault → Tombstone` (plan §D6).

## Atomicity

ACL row deleted → Member row handled per disposition → audit
`MemberRemoved` emitted. Step order is auth-gating truth first
(so a mid-flight crash leaves the auth path workable).

## No-last-admin invariant

Caller is refused with **409 `LastAdminProtected`** if their
removal would leave the community with zero admins. The check
runs inside the same critical section as the ACL delete
(process-wide `LAST_ADMIN_LOCK` mutex). Promote another member
to admin first.

## Dispositions

- `purge` — ACL deleted, Member row deleted outright.
- `tombstone` — ACL deleted, Member row retained with
  `did` + `joinedAt` + `removedAt`; every PII / credential
  field is cleared.
- `historical` — ACL deleted, Member row retained verbatim
  with `removedAt` stamped.
- `policydefault` — resolves to `tombstone` in Phase 1; Phase 2
  swaps in `removal.rego`'s `min_disposition`.

## Audit

`MemberRemoved { disposition, reason: "" }`.
