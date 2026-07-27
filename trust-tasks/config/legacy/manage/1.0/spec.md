---
id: https://trusttasks.org/openvtc/vtc/config/legacy/manage/1.0
title: VTC Legacy — Config Management
status: retired
supersededBy: https://trusttasks.org/spec/vtc/community/profile/show/0.1
version: "1.0"
authors:
  - did:webvh:openvtc.org
applies_to:
  - rest: GET /v1/config
  - rest: PATCH /v1/config
---

# VTC Legacy — Config Management

> **Retired (#710).** `GET, PATCH /v1/config` no longer exists. Every field
> it carried has a canonical owner, verified field by field before removal:
>
> | Legacy field | Canonical owner |
> |---|---|
> | `vtc_did` | `communityDid` on `spec/vtc/community/profile/show/0.1` (`GET /v1/community/profile`, any authenticated session — same reach the legacy GET had) |
> | `vtc_name`, `vtc_description` | `name` / `description` on `spec/vtc/community/profile/{show,update}/0.1` — already the sole write path, which the legacy PATCH delegated to |
> | `public_url` | the `config_store` db-overlay key, read by `spec/config/show/0.1` and written by `spec/config/patch/0.1` (`GET, PATCH /v1/admin/config`) — the same overlay the legacy PATCH wrote |
>
> The immutability guarantee survives the removal structurally rather than
> by a runtime check: `CommunityProfileUpdate` has no `community_did` field,
> and `vtc_did` / `vta_did` are not keys in the config-store `REGISTRY`, so a
> `PATCH /v1/admin/config` naming them is rejected as an unknown key. The
> legacy handler's 409 existed because that surface *could* have rewritten
> them; neither successor can.
>
> Retirement note: the earlier disposition recorded for this task ("strict
> duplicate of `admin/config/manage`") was wrong twice over — that task was
> itself retired, and the two surfaces never overlapped on a single field.
> `/v1/config` carried community identity; `/v1/admin/config` carries
> `server.host` / `server.port` / `log.level`. The correct successors are the
> ones in the table above.

Placeholder Trust Task for the pre-MVP config endpoints (read +
patch) inherited from the `vtc-service` skeleton. Two HTTP methods
share this task because they operate on the same resource.

The shape of this Trust Task will be revised in M0.8 when the
config endpoints get split into `admin/config/show/1.0` /
`admin/config/patch/1.0` / `admin/config/reload/1.0` /
`admin/config/restart/1.0` per spec §14.6.
