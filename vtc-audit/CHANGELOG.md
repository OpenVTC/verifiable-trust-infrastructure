# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.8.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-audit-v0.7.0...vtc-audit-v0.8.0) — 2026-11-28


### Added

- **vtc**: Community events phase 2 — invitations, links, opt-outs, announcements, partners, the event notification ([#2846](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2846))

Implements VTI-EVT-100 – 135 and the `event` notification kind (VTI-NTF-064 – 067).

  - Pins vtc/events/{create,update,show,list,mine/list,registrations/*} at 0.2 (0.1 no longer
    served) and the new 0.1 tasks invitations/{send,list,respond}, invitations/links/{create,
    revoke,redeem}, optouts/{set,list}, announcements/{send,list}.
  - Invitations: one per member per event carrying the member's answer (going/maybe register,
    decline registers nothing); audience invitations under `invite: notify|expect` by the events
    sweeper; host and member invitations widen who may see the event; links with 256-bit codes
    kept only as their SHA-256 digest, answered once and not recorded for redelivery, every
    failure `linkInvalid`; opt-outs per event and per calendar.
  - The `event` notification: the notice row first, the events sweeper its only sender through
    the durable member push; a revision per sequence change, a withdrawal on cancel, revocation or
    leaving the audience; the invitee re-checked before each offering revision; membership,
    directory and group changes kick the sweeper. `vta_sdk::notifications::KIND_EVENT`.
  - Announcements: no sequence change, never in a notification, per-event daily limit.
  - Partners: audience.partners checked (partnerInvalid); a partner's member's presentation is
    verified before the event is looked up (elections::presentation, now built without `voting`);
    partner registrants keyed by DID and counted as othersGoing, never on the roster.
  - Console: invite mode, members-may-invite and partners in the editor; an Invitations tab
    (invitations, invite, links shown once, announcements). Portal: an Invitations tab, opt-outs,
    announcements on the event page, `#/events/join/<code>`.

  Known gaps against the specification, reported for the divergence register: publish/0.1 and
  cancel/0.1 answer the event without invite, membersMayInvite and audience.partners (no 0.2
  versions exist); a partner's member cannot withdraw (withdraw/0.2 carries no presentation,
  VTI-EVT-037/135); a host cannot revoke an invitation (VTI-EVT-103, no task).

- **vtc**: Community events, phase 1 — calendars, events, registrations, hosts ([#2840](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2840))

* wip(vtc): events phase 1 groundwork (capability, keyspace, domain module, pins)



## [0.7.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-audit-v0.2.0...vtc-audit-v0.7.0) — 2026-11-18


### Added

- **vtc-service**: Store and serve an uploaded community logo ([#2751](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2751))

* feat(vtc-service): store and serve an uploaded community logo

  A community can now upload its logo, and the VTC serves it from its own
  origin, so it shows in the console, the member portal, both sign-in
  pages and the default landing page wherever the VTC is hosted.

  Before this, the logo was only the profile's `logoUrl`. Those pages are
  served with `img-src 'self' data:`, so a logo at any other address was
  never drawn, and a deployment with nowhere on the VTC's own origin to
  put a file (a hosted VTC, say) had no logo at all: a filesystem website
  must have its own host, and `admin_ui.members_dir` is a snapshot that
  stops following the daemon on every upgrade.

  What it adds:
  - `vtc/community/logo/update/0.1` (pinned in `vti-specs-vtc`): an
    administrator (`vtc.surface.admin`) sends a PNG, JPEG or WebP, or
    `image: null` to remove the logo. The community re-encodes it as a PNG
    of at most 512 px (`directory::images::reencode_logo`, sharing the
    directory's decoding and its bounds), dropping all metadata and any
    bytes after the image data, and stores it in the `community` keyspace,
    which is backed up. 20 changes per administrator per hour, one
    re-encoding at a time, audited as `CommunityLogoUpdated` by digest.
  - `GET /v1/community/logo`: public, like `public-profile`. Served from
    memory against a small record read, with a fixed `Content-Type`,
    `nosniff`, `default-src 'none'; sandbox`, an `ETag` and `304`. Bytes
    that do not match their record are never served.
  - A `logo` member (`url`, `sha256`, `mediaType`, `width`, `height`) on
    the public profile and on `/v1/member/me`'s `community`. Every page
    draws it in preference to `logoUrl`, which is unchanged.
  - Console: a Logo card on the Community profile page. It rasterizes an
    SVG in the browser, from a `data:` URL inside an `<img>` where it runs
    no script, so no SVG is ever sent or stored. The Logo URL field now
    says when these pages will not draw the address it holds.

  Design note: docs/05-design-notes/vtc-community-logo.md.



## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-audit-v0.1.0...vtc-audit-v0.2.0) — 2026-11-15


## [0.1.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/releases/tag/vtc-audit-v0.1.0) — 2026-11-14


### Changed

- **vtc**: Vtc-audit leaf crate, one regorus engine, typed error codes, trust_tasks split, AdminActor ([#2728](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2728))

* refactor(vti-common)!: move the VTC's audit-event vocabulary to a new vtc-audit leaf crate


