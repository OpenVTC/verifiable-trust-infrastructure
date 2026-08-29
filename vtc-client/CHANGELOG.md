# Changelog

Notable changes to the published crates. Generated from conventional commits by
[git-cliff](https://git-cliff.org) when a release is cut — do not edit by hand.
## [0.5.1](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.5.0...vtc-client-v0.5.1) — 2026-08-29


## [0.5.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.4.0...vtc-client-v0.5.0) — 2026-08-28


### Chore

- **sdk**: Release vta-sdk 0.30.0 for the added CreateKeyBody field ([#1156](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1156))

`CreateKeyBody` gained a `key_id` field while the crate stayed at 0.29.0.
  The struct is exhaustively constructible through the public API, so an
  existing literal no longer compiles — a breaking change under 0.x rules,
  which the semver report has been flagging as its one real finding
  (195 pass, 1 fail) since the field landed.

  Bumps the crate and the nineteen intra-workspace requirements that pin it,
  so `cargo check --workspace` still resolves the path copy and a consumer
  resolving from the registry gets a version that admits the break.



## [0.4.0](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.11...vtc-client-v0.4.0) — 2026-08-26


### Fixed

- **common**: Send the pagination wrapper in camelCase, as the schemas always said ([#1078](https://github.com/OpenVTC/verifiable-trust-infrastructure/pull/1078))

`Paginated<T>` carried no `rename_all`, so every list task sent `next_cursor`
  and `total_estimate` against published schemas that say `nextCursor` and
  `totalEstimate`. A direct R3.1 violation, and the same casing-drift class as
  #656/#658 — where an empty `allowed_contexts` silently minted a super-admin.

  Nothing caught it because nothing compared the two. The service sent one
  spelling, `vtc-client` mirrored the service rather than the schema, and the
  admin SPA typed its fields from the service too. All three agreed with each
  other and none agreed with the contract. The conformance witness added in
  #1076 is what finally put them side by side.

  Four consumers move together: the wrapper in `vti-common`, `vtc-client`'s
  `Page<T>`, and the `joinRequests` and `members` admin plugins. `audit.tsx`
  reads a `cursor` member of a different shape and is untouched.

  ## The count goes 33 → 32, not 33 → 28

  The witness refused 28 and accepted 32, which is the useful part of this
  change and the reason the module doc is rewritten rather than decremented.

  Five entries cited the wrapper. Only `relationships/list` becomes fully
  conforming, because it was the only one whose drift was the wrapper alone —
  its spec types `items` as free objects. The other four still diverge at row
  level (`createdByDid`, `vpClaims`, `MemberResponse` members) and keep their
  entries, now describing only what is left rather than restating a casing bug
  that is fixed.

  Closing a shared root cause moves four entries without closing them. A drift
  count that fell by five would have implied more progress than happened, and
  `known_drift_entries_still_diverge_where_they_say_they_do` is what stopped it
  saying so.



## [0.3.11](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.10...vtc-client-v0.3.11) — 2026-08-22


## [0.3.10](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.9...vtc-client-v0.3.10) — 2026-08-21


## [0.3.9](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.8...vtc-client-v0.3.9) — 2026-08-20


## [0.3.8](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.7...vtc-client-v0.3.8) — 2026-08-18


## [0.3.7](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.6...vtc-client-v0.3.7) — 2026-08-17


## [0.3.6](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.5...vtc-client-v0.3.6) — 2026-08-16


## [0.3.5](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.4...vtc-client-v0.3.5) — 2026-08-14


## [0.3.4](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.3...vtc-client-v0.3.4) — 2026-08-12


## [0.3.3](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.2...vtc-client-v0.3.3) — 2026-08-12


## [0.3.2](https://github.com/OpenVTC/verifiable-trust-infrastructure/compare/vtc-client-v0.3.1...vtc-client-v0.3.2) — 2026-08-12

