# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.2.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vti-voting-v0.1.0...vti-voting-v0.2.0) — 2026-10-26


### Fixed

- **voting**: The ballot box registers only the communities it serves, checks casts off its lock, and pages reads by size ([#2283](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/2283))

Three gaps from the community-voting threat model:

  - Registrations: any DID could register elections until the box's store was full. The service
    config gains `[communities]` — `allowed` community DIDs, or `allow_any = true` for an open box;
    without it nothing registers — and `max_unfinished` (default 20) elections per community not
    yet tallied or cancelled. Another community's registration is `permissionDenied`; one past the
    quota is `unavailable`, which the VTC delivers again until one finishes. A repeat of a
    registration already held is never refused.
  - Locking: a cast's costly checks (the attestation's pairing, a tallied ballot's proofs) ran
    under the one lock over every box, so a flood of casts stalled every other community.
    `BallotBox::cast_check` / `cast_encrypted_check` take the cheap checks and what the costly ones
    need; `CastCheck::run` proves the cast without the box, on a blocking thread (at most one per
    core); `cast_verified` / `cast_encrypted_verified` re-run the cheap checks under the lock and
    admit that one cast. `cast` and `cast_encrypted` still do it all in place.
  - Board reads: a `voting/board/read` page carries at most 256 KiB of entries (always at least
    one), fewer than `limit` where entries are large (read item 4).


