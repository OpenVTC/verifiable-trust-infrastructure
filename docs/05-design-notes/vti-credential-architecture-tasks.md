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

- [x] **0.2 — Wire the crates as VTI deps.** Add `affinidi-sd-jwt-vc`,
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

- [x] **1.1 — `StoredCredential` model + `vault` storage + index.**
  *(format-agnostic — start now, parallel to 0a)*
  - Acceptance: store + get by id; prefix-scan the index by `type`,
    `community_did`, `issuer_did`, `purpose`, `status`. Encrypted at rest
    (existing per-keyspace AES-GCM).
  - Verify: unit tests (`cargo test -p vta-service ... vault`).
  - Files: `vta-service/src/vault/{model,storage,index}.rs`, `server.rs`
    (keyspace wiring; `vault` already exists).

- [x] **1.2 — Receive a credential.** An operation that verifies-minimally
  (issuer signature via the format verifier + not-expired), indexes, and
  stores.
  - Acceptance: receiving a valid SD-JWT-VC (from 0a) stores + indexes it;
    a tampered/expired one is rejected and not stored.
  - Verify: integration test (store, then re-fetch + index hit).
  - Files: `vta-service/src/operations/vault/receive.rs`,
    `vta-service/src/routes/vault.rs` (+ DIDComm handler).

- [x] **1.3 — Local DCQL search → descriptors only.** Match stored
  credentials by `{type, claims, issuer, purpose}`; return **descriptors**
  (never bulk bodies across a trust boundary). **No "list all" endpoint.**
  - Acceptance: a DCQL query for "InvitationCredential for community X"
    returns the matching descriptor; there is no endpoint that enumerates
    the wallet (asserted by a test that the only query path requires a
    DCQL filter).
  - Verify: unit tests for matching + a **negative** test enforcing the
    no-enumeration invariant.
  - Files: `vta-service/src/vault/query.rs` (DCQL match engine).

- [x] **1.3.5 — Consent records (ISO/IEC 27560 + DPV).** *(PR #235 merged; consent bound per-credential via `dct:source` in #237.)* A `ConsentRecord`
  type serializing to the 27560/DPV JSON-LD shape (§7a) + a `consent`
  keyspace (create / get / withdraw / list) + the status event log +
  validity. **Non-repudiation from day one:** every record carries a
  holder `eddsa-jcs-2022` Data Integrity proof signed with the holder's
  **VTA-managed** key (a signed consent receipt). Withdraw appends a
  signed `dpv:ConsentWithdrawn` event.
  - Acceptance: create a signed consent record (verifies; carries
    dataSubject/recipient/purpose/personalData/validity); withdraw flips
    it to ConsentWithdrawn (re-signed) and it no longer authorizes; an
    expired record authorizes nothing; `list`/`get` is the holder's own
    surface (no cross-boundary enumeration). cargo fmt/build/test/clippy/
    deny clean.
  - Verify: unit + integration tests over the consent keyspace.
  - Files: `vta-service/src/vault/consent.rs` (new) + `vault/mod.rs`;
    `affinidi-data-integrity` as a normal `vta-service` dep (signing).
  - Branch: `feat/cred-1.3.5-consent-records`. *(prerequisite for 1.4)*

- [x] **1.4 — Present (consent-gated).** *(PR #237.)* Build a holder-bound,
  selectively-disclosed presentation from a stored credential — a
  **library op** (the wire surface is Phase 3). Signature:
  `present(credential_id, consent_record_id, nonce, aud)`.
  - Acceptance: checks the consent record is *given* / unexpired /
    signature-valid / matches the verifier (`hasRecipient`), derives the
    reveal set from `hasPersonalData`, produces an SD-JWT-VC presentation
    disclosing **only** those claims + a `kb-jwt` signed by the
    **VTA-held holder signer** (injected `&dyn JwtSigner`); refuses a
    revoked/expired credential or a missing/withdrawn consent record;
    a NEGATIVE test proves the disclosed set never exceeds the consented
    set. *(needs 1.3.5 + 0.2)*
  - Verify: integration test (present → verify via `affinidi-sd-jwt`).
  - Files: `vta-service/src/vault/present.rs` (new) + `vault/mod.rs`.
  - Branch: `feat/cred-1.4-vault-present`.

- [x] **1.5 — Mint.** *(PR #236 merged.)* The VTA issues its own SD-JWT-VC via the format
  issuer + the VTA signing key (the signing oracle path).
  - Acceptance: a VTA-minted credential verifies; the issuer key never
    leaves the VTA.
  - Verify: integration test (mint → verify).
  - Files: `vta-service/src/operations/vault/mint.rs`.

- [x] **1.6 — Status refresh.** *(PR #238.)* Poll/refresh status-list state; mark
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

## Phase 2 — DTG catalog + VTC schema store + VIC  (Repo: `vti` + `dtg-credentials`)

**Re-baseline (codebase survey, 2026-06).** Phase 2 is smaller than the
milestone implied — much already exists in `vtc-service`:

- **`dtg-credentials` 0.1.2** (the DTG catalog, a declared-but-**unused**
  crates.io dep) already ships `create::{new_vmc, new_vrc, new_vec,
  new_vic, new_vpc, new_vwc, new_rcard}` over `DTGCredential` / `DTGCommon`
  / `DTGCredentialType{Membership, Relationship, **Invitation**, Persona,
  Endorsement, Witness, RCard}` (W3C VC 2.0, `verify_proof_with_public_key`).
  **`new_vic` IS the InvitationCredential** — VIC is adopt-not-build.
- VTC's current credential builders are **hand-rolled and bypass** the
  catalog: `credentials/{vmc.rs (build_vmc), vec.rs (build_role_vec),
  custom_endorsement.rs}` + `credentials/signer.rs (LocalSigner)`. "Port
  onto DTG" = swap these to `dtg_credentials::create::new_*` signed by the
  existing `LocalSigner`. Callers to update: `ceremony/execute.rs` (Admit →
  membership), `endorsements/`.
- An **`endorsement_types` registry already exists** (`EndorsementType
  {type_uri, claim_schema: Option<JsonValue>, description, created_at,
  created_by_did}` + `storage::{get,store,delete,list,exists}_type` over a
  keyspace) — the proven pattern the `schemas` registry generalises.
- A **`status_lists` keyspace + `status_list/mod.rs` allocator already
  exists** → "every issued credential revocable" reuses it (and this is the
  VTC-side answer to the Phase 1 task 1.5 follow-up). `vmc.rs` already
  attaches `credentialStatus` via `CredentialStatusRef::revocation`.
- **No `schemas` keyspace yet** (net-new). DCQL types for the "accepts"
  half now exist in `affinidi-openid4vp` 0.1.2 (#343 + #344).

Dependency order: **2.0 → (2.1 ∥ 2.2) → 2.3 → 2.4**. 2.4 is gated on the
`affinidi-openid4vp` 0.1.2 publish landing on crates.io.

- [ ] **2.0 — Adopt `dtg-credentials` (DTG catalog).** Wire `dtg-credentials`
  as a real `vtc-service` dep; add a thin `credentials::dtc` layer that
  builds + signs a `DTGCredential` of a given type via the existing
  `LocalSigner` (issuer key never exported). Port `build_vmc`→`new_vmc`,
  `build_role_vec`→`new_vrc`/`new_vec`, `build_custom_endorsement`→`new_vec`;
  update the `ceremony/execute.rs` + `endorsements/` callers.
  - Acceptance: each ported type issues and `verify_proof_with_public_key`
    verifies; issuer key stays in `LocalSigner`; existing ceremony Admit
    still issues a (now DTG) membership. The VC wire shape changes — a
    pre-wire breaking change (greenfield, OK); update affected tests.
  - Verify: unit + the ceremony Admit integration test.
  - Files: `vtc-service/src/credentials/{dtc.rs (new), vmc.rs, vec.rs,
    custom_endorsement.rs, mod.rs}`, `ceremony/execute.rs`,
    `endorsements/mod.rs`; root `Cargo.toml` (`dtg-credentials` → used).
  - Branch: `feat/cred-2.0-adopt-dtc`.

- [ ] **2.1 — InvitationCredential (VIC).** Issue a VIC to a **non-member**
  DID via `dtg_credentials::create::new_vic` + `LocalSigner` + a status-list
  allocation (revocable). Library op (the OOB/sealed delivery transport is
  Phase 3; reuses the relayer≠holder / `sealed_transfer` pattern). Optional
  delegated-invite gate (`can_invite`) deferred to Phase 5.
  - Acceptance: a VTC issues a VIC to a DID with no membership record; it
    verifies; it carries a `credentialStatus` and can be revoked.
  - Verify: unit test (issue VIC to unknown DID → verify + revoke).
  - Files: `vtc-service/src/credentials/invitation.rs (new)` + `mod.rs`;
    `status_list/` (reuse). *(needs 2.0)*
  - Branch: `feat/cred-2.1-invitation`.

- [ ] **2.2 — Schema store: the `schemas` keyspace + Issues registry.** A
  `schemas` keyspace + `SchemaEntry{type_uri, dtc_type (DTGCredentialType
  binding), credential_schema (JSON Schema), kind: Issues, description,
  created_*}` + CRUD, generalising the `endorsement_types` registry. The
  **Issues** half: the types this VTC mints, each with a JSON Schema + DTG
  binding. Admin CRUD endpoints/CLI.
  - Acceptance: register an Issues type with a schema; `list`/`get`/`delete`
    round-trip; issuance (2.0/2.1) consults it (issue refused if the type
    isn't registered as Issues).
  - Verify: unit + integration over the `schemas` keyspace.
  - Files: `vtc-service/src/schemas/{mod.rs, storage.rs, registry.rs}
    (new)`; `routes`/`*_cli` for admin CRUD. *(needs 2.0)*
  - Branch: `feat/cred-2.2-schema-store`.

- [ ] **2.3 — Issue-time schema validation.** When issuing any catalog
    credential, validate the produced VC against its registered
    `credentialSchema` (JSON Schema). Reuse an existing JSON-Schema validator
    crate (check the tree first — likely already present; else add one).
  - Acceptance: a credential whose subject violates its schema is rejected
    at issue; a conforming one passes. Wired into 2.0/2.1 issue paths.
  - Verify: unit (conforming pass / violating reject) per catalog type.
  - Files: `vtc-service/src/schemas/validate.rs (new)`, hooked into
    `credentials/dtc.rs`. *(needs 2.2)*
  - Branch: `feat/cred-2.3-issue-validation`.

- [ ] **2.4 — Schema store: Accepts (DCQL over the registry).** The
    **Accepts** half: criteria the community recognises as evidence,
    expressed as an `affinidi_openid4vp::DcqlQuery` whose `meta.vct_values`
    reference registered schema-store types. This is what a ceremony's
    required-evidence becomes (the join "manifest", now concrete).
  - Acceptance: store an Accepts criterion as a **validated** `DcqlQuery`
    that references only registered types (reject dangling type refs);
    round-trips; retrievable for a ceremony to run via
    `DcqlQuery::match_credentials` (Phase 5).
  - Verify: unit (valid DCQL accepted; one referencing an unregistered type
    rejected).
  - Files: `vtc-service/src/schemas/accepts.rs (new)`; dep
    `affinidi-openid4vp = "0.1.2"`. *(needs 2.2; gated on #344 publish)*
  - Branch: `feat/cred-2.4-accepts-dcql`.

- [ ] CHECKPOINT 2 — each catalog type issues against its schema; a VIC
  issues to a non-member; an Accepts criterion is a DCQL query over the
  registry.

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
