# VTI Credential Architecture — task checklist

Companion to `vti-credential-architecture-plan.md`. Phase 0a + Phase 1 are
task-level (vertical slices, each one complete path). Phases 0b + 2–6 are
milestone-level and get a full task pass at their gate.

Legend — **Repo:** `tdk` = `affinidi-tdk-rs`, `vti` = this workspace.
Each task: **Acceptance** (true when done) · **Verify** (evidence) ·
**Files** (targets).

---

## Phase 0 — Validate + adopt TDK formats  (Repo: `tdk` + `vti`)

> The SD-JWT/-VC + BBS + `bbs_2023` crates already exist and pass tests —
> "build from scratch" was wrong. This phase **adopts** them.

- [x] **0.1 — Validate the foundation builds + passes.** `cargo test -p
  affinidi-bbs -p affinidi-sd-jwt -p affinidi-sd-jwt-vc -p
  affinidi-data-integrity -p affinidi-openid4vp`.
  - Acceptance: exit 0. **DONE** (validated).
  - Verify: ✅ exit 0.

- [ ] **0.2 — Wire the crates as VTI deps.** Add `affinidi-sd-jwt-vc`,
  `affinidi-bbs`, `affinidi-data-integrity` (bbs_2023), `affinidi-openid4vp`
  to the VTI workspace (crates.io versions, or path/git to the local TDK
  for unreleased DCQL).
  - Acceptance: a VTI smoke test issues + verifies an SD-JWT-VC.
  - Verify: `cargo test` in `vta-sdk`/`vti-common` smoke module.
  - Files: `Cargo.toml` (workspace deps), a smoke test.

- [ ] **0.3 — Confirm SD-JWT-VC profile completeness.** Verify
  `affinidi-sd-jwt-vc` carries `vct` / `cnf` / `status`; fill any gap
  upstream (TDK).
  - Acceptance: a typed SD-JWT-VC with `vct`+`cnf`+`status` round-trips.
  - Verify: unit test (TDK).

- [ ] **0.4 — BLS12-381 G2 verification method.** Confirm/add a
  `#bbs-key-0` representation in the did:key/did:webvh layer for the BBS
  issuer key.
  - Acceptance: a `did:webvh` doc resolves a BLS12-381 G2 VM usable by the
    `bbs_2023` verifier.
  - Verify: resolve + verify test (TDK).

- [ ] **0.5 — Schedule the BBS security audit** (gate before BBS signs
  anything real; SD-JWT-VC carries the near-term path meanwhile).

- [ ] **CHECKPOINT 0** — TDK formats wired into VTI; SD-JWT-VC
  issue/verify smoke test green. *Gate: unblocks 1.4–1.6 + Phase 3.*

---

## Phase 0c — DCQL  (Repo: `tdk`, `affinidi-openid4vp`; the one net-new build)

- [ ] **0c.1 — DCQL query model.** The DCQL `credentials` / `claims` /
  `credential_sets` query structures (serde).
  - Acceptance: parse/serialize the DCQL spec examples.
  - Verify: unit tests over spec fixtures.
  - Files: `affinidi-openid4vp/src/dcql/{model,parse}.rs`.

- [ ] **0c.2 — Local match engine.** Match a DCQL query against a set of
  held credentials → the satisfying credential(s)/claims, or no-match.
  - Acceptance: a query for "InvitationCredential with claim X" selects
    only matching held creds; returns descriptors, never the whole set.
  - Verify: unit tests incl. a negative (no-fishing) case.
  - Files: `affinidi-openid4vp/src/dcql/match.rs`.

- [ ] **0c.3 — Format mapping.** Map DCQL onto **SD-JWT-VC** and **BBS**
  credentials (the `format`/`meta` selectors).
  - Acceptance: a DCQL query targets each format and disclosures honour
    the requested claims.
  - Verify: per-format unit tests.

- [ ] **0c.4 — OID4VP integration.** Carry DCQL in the authorization
  request/response alongside (or instead of) DIF PE.
  - Acceptance: a DCQL authorization request → a conforming `vp_token`.
  - Verify: round-trip test.
  - Files: `affinidi-openid4vp/src/authorization*.rs`.

- [ ] **CHECKPOINT 0c** — a DCQL query selects + presents SD-JWT-VC and
  BBS credentials over OID4VP. *Gate: unblocks VTA search (1.3) + Phase 3.*

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

## Phase 0b — BBS (Repo: `tdk`, existing `affinidi-bbs`; adopt + audit)

> `affinidi-bbs` (BBS over `bls12_381_plus`, 52 tests) + the `bbs_2023` DI
> cryptosuite **already exist** — superseding the original "build on
> arkworks" tasks. Remaining is adoption + the audit.

- [x] 0b.1 — BBS sign/verify + proofgen/proofverify exist & pass (52
  tests). **DONE.**
- [x] 0b.2 — `bbs_2023` Data Integrity cryptosuite exists in
  `affinidi-data-integrity`. **DONE.**
- [ ] 0b.3 — Ed25519 holder binding for BBS presentations (confirm/wire
  at integration).
- [ ] 0b.4 — **Independent security review** before BBS signs anything
  real. *(the one real gate)*
- [ ] CHECKPOINT 0b — adopted as a registered credential format; audited
  before real signing. Additive — never blocks SD-JWT-VC or 1–6.

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

- **Track A (`tdk`):** Phase 0c (DCQL) — 0c.1 → … (the one net-new build).
  Phase 0 adopt = validated; BBS audit on its own track.
- **Track B (`vti`):** 1.1 → 1.2 → 1.3 now (format-agnostic); + 0.2 (wire
  the TDK formats as deps); converge at 1.4 (present with SD-JWT-VC).
