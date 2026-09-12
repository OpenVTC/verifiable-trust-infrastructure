# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-dtg-v0.2.2...vti-rooms-dtg-v0.2.3) — 2026-09-12


## [0.2.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-dtg-v0.2.1...vti-rooms-dtg-v0.2.2) — 2026-09-10


## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-dtg-v0.1.2...vti-rooms-dtg-v0.2.0) — 2026-09-09


### Fixed

- **rooms**: A presentation is bound to its presenter — and dtg-credentials 0.6 → 0.9.1 ([#1356](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1356))

* fix(rooms): bind a presentation to its presenter, not to the host

  `pnm-cli rooms --host-did …` could never work. Every request it made was
  refused as `WrongAudience`, and omitting the flag "worked" only by
  skipping the check it exists to perform — so the flag's two states were
  broken and unprotected.

  `audience` is not who a presentation is addressed to.
  `dtg_credentials::authority::verify_chain` compares it to the PRESENTER —
  "the leaf must be presentable by whoever is presenting it" — so it is
  holder binding, and its whole job is to make a captured presentation
  worthless to whoever captured it. Filled with the host's DID it named a
  party no presenter can ever match.

  The value to bind to was already named a few lines away: `RoomSigner`'s
  doc says "a room request is signed by the party the presentation was
  minted for". This passes exactly that. There is no unbound case left, so
  the warning about one goes, and `--host-did` keeps its real job of naming
  the document's recipient.

  ## The spec says otherwise, and that is filed separately

  `rooms/keys/present/0.1` describes `audience` as "the party the
  presentation is for … a host's identifier, normally". The CLI implemented
  the spec faithfully; the spec and the credential library it runs on
  disagree, identically in dtg-credentials 0.6 and 0.7, so it is not
  version drift.

  This changes the CLI to match the verifier rather than the prose, because
  a presentation that cannot verify protects nobody while being wrong in
  the other direction. Which side should move is a working-group question —
  0.7's own notes point at upstream PR #41, "a key-control demonstration at
  invocation, which removes `audience` as redundant" — and is raised there.

  * fix(rooms)!: stop sending `audience` and `nonce` on rooms/keys/present

  Completes the previous commit, which repointed `audience` at the presenter so
  it would at least verify. It should not be sent at all, and neither should
  `nonce`. Both are removed from `rooms/keys/present` by spec 0.2.

  `audience` named the party that had to PRESENT a credential, not the one it was
  addressed to — so a host DID named somebody no presenter can ever be, and the
  host refused every request. That is now moot: dtg-credentials 0.8.0 removed the
  property and made the real rule explicit, which the VTA was already satisfying.
  The leaf grants to the DID this VTA authenticated, and a host refuses a chain
  whose leaf grants to anyone else. Who may present is established, not declared.

  `nonce` was written into the presentation object, which is closed and has no
  member for it — so a caller supplying one got a presentation the host rejects
  as malformed. It could not have been made to work: every signature in a
  presentation is an ISSUER's, never the presenter's, so a challenge inside it is
  unauthenticated and a replay copies it along with everything else. Freshness is
  the request's, via `issuedAt` and the duplicate-execution rule keyed on
  document `id`.

  ## A second live instance, found while doing this

  `rooms/keys/backfill` passed the caller-named host as the audience in
  `vta-service`, exactly as that spec's normative MUST instructed. Every backfill
  this VTA attempted was refused for the same reason. What actually makes a
  caller-named host safe is that the leaf grants to the VTA: naming a host
  transfers no standing. It does hand that host sight of the principal's
  credentials, which is a disclosure rather than an escalation, and the comment
  now says so.

  ## Nothing binds a presentation to a host, deliberately

  A chain is scoped to the ROOM. One rooted in a room confers nothing anywhere
  else, and any host serving that room would honour it — a room may have more
  than one host, and moving between them without reissuing credentials is the
  point. Binding a request to its destination is `recipient` on the document that
  carries the presentation, per SPEC.md §4.8.2, which its proof covers.



## [0.1.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-dtg-v0.1.1...vti-rooms-dtg-v0.1.2) — 2026-09-07


## [0.1.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-rooms-dtg-v0.1.0...vti-rooms-dtg-v0.1.1) — 2026-09-07

