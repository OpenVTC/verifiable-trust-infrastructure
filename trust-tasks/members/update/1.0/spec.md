---
id: https://trusttasks.org/openvtc/vtc/members/update/1.0
title: VTC Members — Update
status: retired
supersededBy: https://trusttasks.org/spec/vtc/members/update/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: PATCH /v1/members/{did}
---

# VTC Members — Update

Updates the role or non-credential metadata of a member. Spec
§10.4.

## Authentication

`AdminAuth`. Phase 1 keeps a uniform admin gate; spec §5.3's
permission matrix (Moderator-tier removal etc.) lands when the
auth layer becomes VtcRole-aware in Phase 2.

## Body

```
{
  "role":                ? VtcRole (excl. "admin"),
  "publishConsent":      ? bool,
  "departurePreference": ? "purge" | "tombstone" | "historical" | "policydefault",
  "extensions":          ? object  (≤ 16 KiB)
}
```

Every field is optional; a body with no fields is a no-op
(`200 OK` returning the current row).

## Errors

- `400 Bad Request` — `role: "admin"` — refused with an
  operator-facing hint pointing at
  `POST /v1/members/{did}/promote-to-admin`. The promote-to-admin
  endpoint runs the required step-up UV ceremony (spec §10.4).
- `401 Unauthorized`, `403 Forbidden` — auth.
- `404 Not Found` — member or matching ACL row absent.

## Audit

- `RoleChanged { previousRole, newRole }` when the role changes.
- `MemberUpdated { fieldsChanged: [...] }` when one or more
  non-role fields change. Both events fire if both kinds of
  change land in the same PATCH.
