# VTI Credential Architecture — task checklist

Companion to `vti-credential-architecture-plan.md`. Phase 0a + Phase 1 are
task-level (vertical slices, each one complete path). Phases 0b + 2–6 are
milestone-level and get a full task pass at their gate.

Legend — **Repo:** `tdk` = `affinidi-tdk-rs`, `vti` = this workspace.
Each task: **Acceptance** (true when done) · **Verify** (evidence) ·
**Files** (targets).

---

## Phase 0a — SD-JWT-VC  (Repo: `tdk`, new crate `affinidi-sd-jwt`)

- [ ] **0a.1 — SD-JWT core round-trip.** Build an SD-JWT (issuer JWT with
  an `_sd` digest array + appended `~`-separated disclosures), serialize,
  parse, and verify the issuer signature + recompute every disclosure
  digest.
  - Acceptance: a credential with all claims disclosed verifies; flipping
    one byte of a disclosure or the signature fails verification.
  - Verify: unit tests (`cargo test -p affinidi-sd-jwt`).
  - Files: `affinidi-sd-jwt/src/{lib,sd_jwt,disclosure,hash}.rs`.

- [ ] **0a.2 — Selective disclosure.** Holder presents a *subset* of
  disclosures; verifier returns only revealed claims; undisclosed claims
  are absent and unrecoverable from the digests.
  - Acceptance: present `{a}` of `{a,b,c}` → verifier sees `a`, never
    `b`/`c`; the digests of `b`/`c` reveal nothing.
  - Verify: unit test asserting the disclosed set and the absence of the
    rest.
  - Files: `affinidi-sd-jwt/src/present.rs`, `verify.rs`.

- [ ] **0a.3 — Key binding (`kb-jwt`).** Holder appends a `kb-jwt` over
  `(sd_hash, aud, nonce, iat)` signed by the holder key (`cnf`); verifier
  enforces it.
  - Acceptance: a presentation with no / wrong / replayed (stale
    `nonce`/`aud`) `kb-jwt` is rejected; a correct one passes and yields
    the bound holder DID.
  - Verify: unit tests for each rejection case + the happy path.
  - Files: `affinidi-sd-jwt/src/key_binding.rs`, `verify.rs`.

- [ ] **0a.4 — SD-JWT-VC profile.** Add the VC profile fields: `vct`
  (credential type), `iss`, `cnf`, `status`, `iat`/`exp`; map to the
  workspace VC semantics.
  - Acceptance: a typed SD-JWT-VC issues + verifies carrying
    `vct`+`cnf`+`status`; an unknown/absent `vct` is surfaced to the
    caller.
  - Verify: unit test + a committed fixture credential.
  - Files: `affinidi-sd-jwt/src/vc.rs`, `fixtures/`.

- [ ] **0a.5 — IETF interop fixtures.** Validate against the published
  SD-JWT / SD-JWT-VC examples (known-answer tests).
  - Acceptance: the IETF example issuance + presentation verify;
    digests/disclosures match byte-for-byte where the spec fixes them.
  - Verify: KAT tests over `fixtures/ietf/`.
  - Files: `affinidi-sd-jwt/tests/interop.rs`, `fixtures/ietf/`.

- [ ] **0a.6 — Public API + docs.** Stabilise `issue(claims, sd_paths,
  issuer_key)`, `present(sd_jwt, reveal, holder_key, nonce, aud)`,
  `verify(presentation, trusted_issuer) -> {claims, holder_did}`.
  - Acceptance: the three-call flow runs in a doctest; the API is what the
    VTA store (1.4/1.5) and the exchange (P3) will consume.
  - Verify: doctest + `cargo doc` clean.
  - Files: `affinidi-sd-jwt/src/lib.rs` (public surface).

- [ ] **CHECKPOINT 0a** — crate green end-to-end (issue → disclose →
  verify + binding) + IETF fixtures pass; wired as a path/git dep into
  this workspace. *Gate: unblocks 1.4–1.6 and Phase 3.*

---

## Phase 1 — VTA credential store  (Repo: `vti`, `vta-service`)

- [ ] **1.1 — `StoredCredential` model + `vault` storage + index.**
  *(format-agnostic — start now, parallel to 0a)*
  - Acceptance: store + get by id; prefix-scan the index by `type`,
    `community_did`, `issuer_did`, `purpose`, `status`. Encrypted at rest
    (existing per-keyspace AES-GCM).
  - Verify: unit tests (`cargo test -p vta-service ... vault`).
  - Files: `vta-service/src/vault/{model,storage,index}.rs`, `server.rs`
    (keyspace wiring; `vault` already exists).

- [ ] **1.2 — Receive a credential.** An operation that verifies-minimally
  (issuer signature via the format verifier + not-expired), indexes, and
  stores.
  - Acceptance: receiving a valid SD-JWT-VC (from 0a) stores + indexes it;
    a tampered/expired one is rejected and not stored.
  - Verify: integration test (store, then re-fetch + index hit).
  - Files: `vta-service/src/operations/vault/receive.rs`,
    `vta-service/src/routes/vault.rs` (+ DIDComm handler).

- [ ] **1.3 — Local DCQL search → descriptors only.** Match stored
  credentials by `{type, claims, issuer, purpose}`; return **descriptors**
  (never bulk bodies across a trust boundary). **No "list all" endpoint.**
  - Acceptance: a DCQL query for "InvitationCredential for community X"
    returns the matching descriptor; there is no endpoint that enumerates
    the wallet (asserted by a test that the only query path requires a
    DCQL filter).
  - Verify: unit tests for matching + a **negative** test enforcing the
    no-enumeration invariant.
  - Files: `vta-service/src/vault/query.rs` (DCQL match engine).

- [ ] **1.4 — Present.** Build a presentation from a stored credential +
  a holder-signed consent/selection → an SD-JWT-VC presentation with
  `kb-jwt`.
  - Acceptance: presenting a consented credential yields a verifiable
    presentation (disclosing only the requested claims); without a valid
    consent token the VTA refuses. *(needs 0a)*
  - Verify: integration test (present → verify via `affinidi-sd-jwt`).
  - Files: `vta-service/src/operations/vault/present.rs`, `routes/vault.rs`.

- [ ] **1.5 — Mint.** The VTA issues its own SD-JWT-VC via the format
  issuer + the VTA signing key (the signing oracle path).
  - Acceptance: a VTA-minted credential verifies; the issuer key never
    leaves the VTA.
  - Verify: integration test (mint → verify).
  - Files: `vta-service/src/operations/vault/mint.rs`.

- [ ] **1.6 — Status refresh.** Poll/refresh status-list state; mark
  revoked/expired so search + present exclude them.
  - Acceptance: a credential whose status-list bit is set is excluded from
    search results and refused for presentation.
  - Verify: unit test flipping a status bit → excluded.
  - Files: `vta-service/src/vault/status.rs`.

- [ ] **CHECKPOINT 1** — VTA stores / searches / presents / mints
  SD-JWT-VC end-to-end; the no-enumeration + consent-before-presentation
  invariants are test-enforced. *Gate: unblocks Phase 3.*

---

## Phase 0b — BBS foundation  (Repo: `tdk`, new crate `affinidi-bbs`; gated/audited)

- [ ] 0b.1 — Adopt `ark-bls12-381`; BLS12-381 G2 keygen; implement
  `affinidi-crypto` key/DID/multikey traits (`#bbs-key-0`, multicodec
  `0xeb`).
- [ ] 0b.2 — `bbs-2023` sign/verify vs IRTF test vectors.
- [ ] 0b.3 — `bbs-2023` proofgen/proofverify (selective disclosure) vs
  IRTF vectors.
- [ ] 0b.4 — `bbs-2023` Data Integrity cryptosuite in
  `affinidi-data-integrity`.
- [ ] 0b.5 — Ed25519 holder binding for BBS presentations.
- [ ] 0b.6 — **Security review** before any real signing.
- [ ] CHECKPOINT 0b — IRTF vectors pass + e2e issue/disclose/verify;
  audited. Additive to the credential-format registry.

---

## Phase 2 — DTC catalog + VTC schema store + VIC  (Repo: `vti` + `dtg-credentials`)

- [ ] 2.1 — Adopt `dtg-credentials`; port VMC/VEC onto DTC types (thin
  wrappers).
- [ ] 2.2 — VTC `schemas` keyspace + registry (issues + accepts; JSON
  Schema + DTC binding) + admin CRUD.
- [ ] 2.3 — InvitationCredential (VIC) builder (DTC).
- [ ] 2.4 — Issue-time schema validation for every issued credential.
- [ ] CHECKPOINT 2 — each catalog type issues against its schema.

---

## Phase 3 — credential-exchange protocol  (Repo: `vti`: `vta-sdk` + `vta-service` + `vtc-service`)

- [ ] 3.1 — `credential-exchange/*` Trust Task message types
  (`offer`/`request`/`issue` + `query`/`present`) wrapping OID4VCI/OID4VP
  bodies + DCQL — in `vta-sdk/src/protocols/credential_exchange/`.
- [ ] 3.2 — Issuer side (VTC): `offer → issue` (OID4VCI).
- [ ] 3.3 — Verifier side (VTC): `query (DCQL) → present (OID4VP)`
  verification.
- [ ] 3.4 — Holder side (VTA): handle `offer→request→store`;
  `query→consent→present`.
- [ ] 3.5 — relayer≠holder + `sealed_transfer` for secret-bearing
  issuance.
- [ ] CHECKPOINT 3 — VTC↔VTA issue + query + present round-trips.

---

## Phase 4 — role-by-VC + verified-assertion cache + VP-based `/auth`  (Repo: `vti`: `vti-common` + `vtc-service`)

- [ ] 4.1 — `verified_assertions` keyspace + record (roles/contexts/
  membership/proof_refs/verified_at/expires_at/invalidated) + TTL.
- [ ] 4.2 — `/auth/challenge` (DCQL) + `/auth` (verify VP → write
  assertion → mint a JWT derived from it).
- [ ] 4.3 — Auth extractors (`AdminAuth`/`ManageAuth`/`StepUpAuth`) read
  the assertion record, not the JWT `role`.
- [ ] 4.4 — Revocation/role-change → invalidate the record (push) + TTL
  (pull); define the max staleness window.
- [ ] 4.5 — Ceremony `Admit`/`Remint`/`Depart` issue/revoke Role VCs +
  update the cache; ACL → derived index.
- [ ] CHECKPOINT 4 — admin proven by a held Role VC; revocation
  invalidates within the window.

---

## Phase 5 — join ceremony integration  (Repo: `vti`: `vtc-service`)

- [ ] 5.1 — "join" ceremony emits a DCQL query from the schema store's
  required evidence.
- [ ] 5.2 — Holder presents → ceremony assembles `Facts` from the
  verified VP → `decide()` → `execute()`.
- [ ] 5.3 — Allow → issue MembershipCredential (+ Role VC) back via the
  exchange; deny → decision-trace reason; refer → moderator queue;
  request_more → DCQL loop.
- [ ] CHECKPOINT 5 — the spec §12 invite→join flow end-to-end (allow +
  deny).

---

## Phase 6 — browser plugin UX  (Repo: browser plugin + `vta-mobile-core`)

- [ ] 6.1 — Digital Credentials API → OID4VP request handling.
- [ ] 6.2 — Plain-English consent (reuse the ceremony English renderer) +
  per-claim disclosure.
- [ ] 6.3 — Device-side holder-binding signature + invite→join progress
  UI.
- [ ] CHECKPOINT 6 — Alice completes invite→join in the plugin.

---

## Start here (parallel)

- **Track A (`tdk`):** 0a.1 → … → CHECKPOINT 0a. (0b on the audited track.)
- **Track B (`vti`):** 1.1 → 1.2 → 1.3 now (format-agnostic); converge
  with 0a at 1.4.
