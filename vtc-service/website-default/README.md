# vtc-service default community website

In-tree default landing page served when the operator has not set
`website.root_dir` in the daemon config.

This is a fallback so a fresh `cargo run` produces a working
`GET /` response instead of a 503. The page fetches
`/v1/community/public-profile` + `/health` and renders them; until the
profile is populated, the placeholder copy in `index.html` is
shown.

Around that live data it introduces a VTC to a visitor: a "Join this
community" button to the member portal's join page (`/members/?join`, where
the browser wallet sends a join request an administrator reviews), a link to
<https://openvtc.net>, member sign-in at `/members/` (the member portal), the community's capabilities (git repositories governed across
GitHub, Forgejo, Codeberg and Gitea; verifiable data rooms; access
management; membership credentials; cross-community recognition), and a
quieter link to the operator console at `/admin/`.

The page is served under `default-src 'self'`: no inline scripts, no
inline `style` attributes, and every image is same-origin or inline SVG.

Its look comes from the community's shared design tokens and type:

- `tokens.css` is a copy of `admin-ui/src/styles/tokens.css`, the token
  file the member portal and the operator console also use. Edit the
  source and copy it here; a test in `src/website/default_site.rs` fails
  if the two differ.
- `fonts.css` and `fonts/` self-host IBM Plex Sans and IBM Plex Mono
  (SIL Open Font License 1.1, `fonts/OFL-*.txt`), copied from the
  @fontsource packages the console bundles.

A custom site in `website.root_dir` needs neither file; it keeps working
with whatever it links itself.

`theme.js` is the colour-theme switcher in the top bar (Match system /
Light / Dark). It is loaded in `<head>` without `defer`, so a pinned theme
lands before first paint, and it stores the choice under the same
localStorage key as the member portal and the operator console
(`vtc-admin-theme`), so one choice holds on all three. Without JavaScript
the switcher stays hidden and the page follows the system setting.

Baked at compile time by `include_dir!` (see
`src/website/default_site.rs`). Served by the `/` catch-all
sub-router **only** when:

- The `website` cargo feature is on.
- Neither `website.root_dir` nor `website.landing_dir` is set.

Operators wanting their own landing page don't edit this directory and
rebuild: `vtc website export <dir>` writes these files out, and
`website.landing_dir = "<dir>"` serves them from disk, re-read on every
request, on the same host as the console. `website.root_dir` instead
serves a deployable site, on a host of its own (the filesystem-backed
handler in `src/website/serve.rs`).
