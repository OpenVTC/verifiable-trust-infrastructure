# vtc-service default community website

In-tree default landing page served when the operator has not set
`website.root_dir` in the daemon config.

This is a fallback so a fresh `cargo run` produces a working
`GET /` response instead of a 503. The page fetches
`/v1/community/public-profile` + `/health` and renders them; until the
profile is populated, the placeholder copy in `index.html` is
shown.

Around that live data it introduces a VTC to a visitor: a "Get started"
link to <https://openvtc.net>, member sign-in at `/members/` (the member
portal), the community's capabilities (git repositories governed across
GitHub, Forgejo, Codeberg and Gitea; verifiable data rooms; access
management; membership credentials; cross-community recognition), and a
quieter link to the operator console at `/admin/`.

The page is served under `default-src 'self'`: no inline scripts, no
inline `style` attributes, and every image is same-origin or inline SVG.

Baked at compile time by `include_dir!` (see
`src/website/default_site.rs`). Served by the `/` catch-all
sub-router **only** when:

- The `website` cargo feature is on.
- `website.root_dir` is unset.

Once the operator sets `website.root_dir`, the filesystem-backed
handler from `src/website/serve.rs` takes over and this default
becomes unreachable.

Operators wanting a richer "out of the box" landing page replace
the files in this directory (or, more commonly, configure
`website.root_dir` and populate that directory with their own
content).
