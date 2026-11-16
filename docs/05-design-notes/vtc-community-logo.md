# A community logo the VTC stores and serves

Status: implemented (`vtc/community/logo/update/0.1`, `GET /v1/community/logo`).

## The problem

A community's logo used to be only `CommunityProfile.logoUrl`: an address.
The console, the member portal, their sign-in pages and the default landing
page are all served with the CSP `img-src 'self' data:`, so they draw a logo
only from the VTC's own origin (`admin-ui/src/lib/display-logo.ts`,
`displayableLogo`). Anything else falls back to the gradient mark.

A deployment with nowhere on that origin to put a file therefore had no logo
at all. A hosted VTC (a VTA Farm session, say) is exactly that case:

- a filesystem website (`[website] root_dir`) must have its own
  `routing.website.host` (`validate_website_isolation`), so it is never the
  origin `/members` and `/admin` are served from;
- `[admin_ui] members_dir` serves a copy of the portal, which works, but the
  copy is a snapshot that stops following the daemon on every upgrade.

## The decision

The community stores the image itself and serves it from its own origin.

- **The write** is a Trust Task, `vtc/community/logo/update/0.1`, signed by an
  administrator (`vtc.surface.admin`), carrying the image or `image: null` to
  remove it.
- **The read** is a public, unauthenticated `GET /v1/community/logo`, beside
  `public-profile` and `did-qr.svg`. An `<img>` cannot send a signed document,
  and the sign-in pages draw the logo before the visitor has any identity.
- **Pages learn of it** through a `logo` member of the public profile and of
  the portal's `/v1/member/me` `community`: `{ url, sha256, mediaType, width,
  height }`, with `url = /v1/community/logo?v=<first 16 hex of the digest>`, so
  a replaced logo is a new URL and no cache serves the old one. Every page draws
  `logo.url` in preference to `logoUrl` (`chosenLogo`).

## Choices and why

1. **`logoUrl` is left alone.** The stored logo is separate state, never written
   into `logoUrl`. `CommunityProfileUpdate::apply` accepts only `http(s)://`
   there, so a relative path would be refused by `profile/update` and by config
   import, and the profile form would fight it. `logoUrl` also stays useful as
   an address for readers that fetch from anywhere.
2. **No `dryRun`, no `logo/show` task.** A theme has a profile to check against,
   so a dry run means something. A logo has nothing to check but whether it
   decodes, and a dry run would be unaudited decoding on demand. The public GET
   is the read.
3. **Stored as PNG, always.** `directory::images::reencode` writes JPEG for an
   opaque image, which suits a photograph and smears a logo's flat colour and
   sharp edges. `reencode_logo` shares the decoding and its bounds and always
   encodes PNG, stepping the size down until it fits 256 KiB.
4. **No SVG, anywhere.** An SVG served from the community's origin is a document
   that can run script there if opened directly, so the schema admits only PNG,
   JPEG and WebP. The console rasterizes an SVG itself (`lib/logo-upload.ts`): it
   draws it from a `data:` URL into an `<img>`, where an SVG runs no script and
   loads nothing, and then onto a canvas. It uses a `data:` URL rather than a
   `blob:` one because the console's CSP admits only `data:`.

## Security properties, and where each is held

| Property | Where |
|---|---|
| Only an administrator writes; checked before any decoding | `surface_tasks::handle_logo_update` (`as_capable`, `SurfaceAdmin`) |
| Bytes bounded before decoding; pixels and decode memory bounded while decoding | `directory::images::decode` (256 KiB, 8192 px, 128 MiB) |
| Decoded strictly as the declared type, never sniffed | `directory::images::decode` (`ImageReader::with_format`) |
| No received byte stored: metadata, text chunks and trailing polyglot payloads gone | `reencode_logo`; `a_logo_keeps_no_text_chunk_metadata_or_trailing_bytes` |
| Per-signer rate limit (20 an hour), one re-encoding at a time | `community::logo::LogoState` |
| Audited by digest, never the image; no change without its record | `community::ops::logo`, `CommunityLogoUpdated` |
| Served as an image only: fixed `Content-Type`, `nosniff`, `default-src 'none'; sandbox` | `routes::community::logo` |
| A record that does not match its bytes, or names another type, is never served | `LogoState::served`, `LogoMeta::well_formed` |
| No session, no cookie; nothing a visitor reveals | `routes::community::logo` (public, ungoverned like `public-profile`) |

The route reads only the small record on each request and serves the bytes
from memory, keyed by digest, and answers `304` on a matching `ETag`. It sits
off the unauthenticated governor, like `public-profile`, because pages load it
on every navigation and the governor refills one request every five seconds.

## What travels where

- **Backups**: both rows live in the `community` keyspace, which is backed up.
- **Config export/import**: not carried. A logo is an image, not configuration.
- **Join-manifest branding** (`vtc/community/branding`): unchanged. An
  administrator who wants the stored logo there can set branding's `logoUrl` to
  the absolute `https://<host>/v1/community/logo`.

## Code

- Spec: `vtc/community/logo/update/0.1` (dtgwg-trust-tasks-tf), pinned in
  `vti-specs-vtc`.
- `vtc-service/src/community/{logo,ops/logo}.rs`,
  `vtc-service/src/directory/images.rs` (`reencode_logo`),
  `vtc-service/src/routes/community/logo.rs`,
  `vtc-service/src/trust_tasks/surface_tasks.rs`,
  `vtc-audit/src/event.rs` (`CommunityLogoUpdated`).
- Console: `admin-ui/src/plugins/community/LogoCard.tsx`,
  `admin-ui/src/lib/{logo-upload,display-logo}.ts`; landing page:
  `website-default/site.js`.
- Tests: `vtc-service/tests/it/community_logo.rs`, and the unit tests beside
  each module.
