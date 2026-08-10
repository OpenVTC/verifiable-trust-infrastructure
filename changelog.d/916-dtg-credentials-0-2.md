### vtc-service 0.11.54 — dtg-credentials 0.2 (#916)

Moves the workspace from `dtg-credentials` 0.1.3 to 0.2, tracking DTG Core
Credentials **Working Draft 01**. The catalog is the source of truth for the
canonical wire shape of every credential the VTC mints, so staying a spec draft
behind means issuing a form the rest of the ecosystem has moved off.

#### Nothing we mint changed

Verified rather than assumed: the emitted VMC, VEC and VIC documents are
**byte-identical** across the bump — same `@context` (both URIs, same order),
same `type` array, same `credentialSubject` shape. Checked by emitting all three
under 0.1.3 and 0.2.0 and diffing, not by reading the changelog.

A 0.x minor bump is semver-breaking and this crate fixes wire shapes, so "it
compiles" was never sufficient: the constructors could have kept their signatures
while every credential quietly became a different document.

#### What 0.2 actually changes, and why none of it reaches us

- **`taskContext` is REQUIRED on Witness credentials (VWC).** Parsing a VWC
  without one is now `MissingTaskContext`. We construct only VMC/VEC/VIC; the
  `WitnessCredential` references in `ceremony/` and `policy/` are JSON string
  literals in the decision pipeline and never round-trip through `DTGCredential`.
  **Worth knowing before that changes**: the day the VTC parses a witness
  credential through this crate, it must carry a `taskContext`.
- **`digest_multibase()` / `verify_digest()` are new** — SHA-256 over JCS,
  multihash, base58btc multibase. Deliberately *not* the
  `sha256:<lowercase-hex>` of Working Draft 01. Same underlying hash, different
  encoding; the same hex → `digestMultibase` move trust-tasks 0.4 made in #911.
- **`DTGCredentialType::RCard` is deprecated.** The R-Card was removed as a DTG
  credential *type* in WD-01 — it is a verifiable data structure, to be defined
  by the planned DTG VDS spec. We never constructed one; the `VtcRole::Issuer`
  doc comment that listed it is corrected.

No new transitive dependencies — `multibase`, `sha2` and
`serde_json_canonicalizer` were already in the tree. `cargo deny` clean on
advisories, bans, licenses and sources.

#### The gap this exposed

The existing tests asserted the `type` array but **nothing asserted `@context`**,
so a changed context would have compiled, passed 85 credential tests, and shipped
a document no one else in the ecosystem recognises. Four new tests pin
`@context` and `type` exactly — including order, which is load-bearing in JSON-LD
because a later context overlays an earlier one.

Verified by canary: flipping the expected context fails all four with
`@context drifted`. A future failure there is not automatically a defect — the
catalog is allowed to move — but it forces the change to be deliberate and
coordinated rather than silent.
