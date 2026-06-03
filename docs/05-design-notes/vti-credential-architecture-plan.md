# VTI Credential Architecture — implementation plan

**Phase:** PLAN (spec-driven). Companion to
`vti-credential-architecture.md` (the SPECIFY artifact, PR #230) and
`vti-credential-architecture-tasks.md` (the task checklist).

This plan turns the spec into a dependency-ordered, vertically-sliced
build. Phase 0a (SD-JWT-VC) and Phase 1 (VTA credential store) are
detailed to task level; later phases are milestone-level and get their
own PLAN pass before they start.

---

## Two repositories

The work spans two repos. Get the boundary right or the dependency graph
lies.

| Repo | Owns |
|---|---|
| **`affinidi-tdk-rs`** (external; published crates) | the credential *crypto + formats* — **already built + validated**: `affinidi-sd-jwt`/`-vc`, `affinidi-bbs` (BBS over `bls12_381_plus`), `affinidi-data-integrity::bbs_2023`, `affinidi-openid4vp`/`-vci`. One net-new gap: **DCQL**. |
| **`verifiable-trust-infrastructure`** (this workspace) | everything that *uses* credentials: the VTA store, VTC schema store + issuer, the exchange protocol, role-by-VC + the verified-assertion cache, the ceremony integration, plugin UX. |

> **Re-baseline (validated):** the credential foundation the spec once
> said to "build from scratch" **already exists in the TDK and passes its
> tests** (`cargo test` exit 0 across the crates). Phase 0 is therefore
> **validate + adopt**, not build — the BBS curve is `bls12_381_plus`
> (keep `affinidi-bbs`, not `arkworks`), and the only net-new TDK work is
> **DCQL**. This collapses the original Phase 0a/0b into a short adoption
> step and moves the real work to DCQL + Phases 1–6.

**Coordination rule:** a this-repo phase that consumes a TDK format wires
it as a dep (the crates are `publish.workspace = true` — crates.io, like
the `affinidi-vc = "0.1"` deps VTI already uses; path/git to the local
TDK for unreleased changes like DCQL).

---

## Dependency graph

```
                 ┌─────────────────────────── (affinidi-tdk-rs) ───────────────────────────┐
   Phase 0   validate + adopt SD-JWT-VC + BBS (DONE: tests green) ─┐
   Phase 0c  DCQL  (the one net-new TDK build) ───────────────────┤
                                                                  │
                 └────────────────────────────────────────────────│── (verifiable-trust-infrastructure) ──┘
                                                                  ▼
   Phase 1   VTA credential store    │   1.1–1.3 (model / receive / search) are FORMAT-AGNOSTIC →
             ────────────────────────┘   can start NOW (adopt SD-JWT-VC at 1.4).
                                         1.4–1.6 (present / mint / status) wire the adopted format.
                                     ▼
   Phase 2   DTG catalog + VTC schema store + VIC
                                     ▼
   Phase 3   credential-exchange protocol  (Trust-Tasks ⊃ OID4VCI/OID4VP + DCQL)
                                     ▼
   Phase 4   role-by-VC + verified-assertion cache + VP-based /auth
                                     ▼
   Phase 5   join ceremony integration  (plugs into the existing decision pipeline)
                                     ▼
   Phase 6   browser plugin UX  (Digital Credentials API)
```

**What can start immediately, in parallel:**
- **Track A (affinidi-tdk-rs):** Phase 0c (DCQL) — the one net-new TDK
  build. (Phase 0 adopt = already validated; BBS audit on its own track.)
- **Track B (this repo):** Phase 1 tasks **1.1–1.3** — the
  `StoredCredential` model, the `vault` keyspace + index, and local
  DCQL-shaped search — are format-agnostic (they index opaque credential
  bodies + metadata). They converge with the adopted SD-JWT-VC at task 1.4
  (present).

---

## Vertical slicing principle

Every task is **one complete path**, not a horizontal layer. For SD-JWT
that means "issue → disclose → verify a credential with N claims" as a
single slice, not "all issuance, then all verification." For the store it
means "store + index + retrieve one credential end-to-end" before adding
search, then present.

---

## Phase 0 — Validate + adopt the TDK formats  (repo: `affinidi-tdk-rs`; mostly DONE)

The credential foundation already exists and passes its tests. Validated
`cargo test` (exit 0) across `affinidi-sd-jwt` (90), `affinidi-sd-jwt-vc`
(11), `affinidi-bbs` (52, BBS over `bls12_381_plus`),
`affinidi-data-integrity` (incl. `bbs_2023`), `affinidi-openid4vp`/`-vci`.

Remaining adoption work (small): wire the crates as VTI deps; confirm the
SD-JWT-VC profile carries `vct`/`cnf`/`status`; confirm/add a BLS12-381 G2
verification-method representation for `#bbs-key-0` in the
did:key/did:webvh layer; schedule the **BBS security audit** (the crate is
unit-tested, not yet independently audited) as a gate before BBS signs
anything real.

**CHECKPOINT 0:** the TDK credential crates wired as VTI deps; a smoke
test issues + verifies an SD-JWT-VC from this workspace. *Unblocks Phase 1
present/mint and Phase 3.*

---

## Phase 0c — DCQL  (repo: `affinidi-tdk-rs`; the one net-new build)

**Goal:** the Digital Credentials Query Language — the privacy-first,
"no fishing" query model (§7). `affinidi-openid4vp` uses the older DIF
Presentation Exchange (`PresentationDefinition`/`InputDescriptor`) today;
DCQL is absent across the whole TDK.

Slices: a DCQL query/credential-set model → a local match engine against
held credentials → mapping onto both the SD-JWT-VC and BBS formats →
integration with the OID4VP authorization request/response.

**CHECKPOINT 0c:** a DCQL query selects matching credentials (SD-JWT-VC +
BBS) and produces an OID4VP presentation. *Unblocks the VTA local search
(1.3) and the exchange (Phase 3).*

---

## Phase 1 — VTA credential store  (repo: this workspace, `vta-service`)

**Goal:** promote the `vault` keyspace from M1 read-only stub to a real
credential store: receive, index, search (DCQL, local), present, mint —
the data plane the spec §5 describes.

Slices (detail in the tasks doc):
1. `StoredCredential` model + `vault` storage + index (by type / community
   / issuer / purpose / status). **Format-agnostic — start now.**
2. Receive (verify-minimally → index → store).
3. Local DCQL search → **descriptors only** (the no-enumeration invariant).
4. Present (stored cred + holder-signed consent → SD-JWT-VC presentation).
5. Mint (VTA issues its own SD-JWT-VC).
6. Status refresh (revoked/expired excluded from search/present).

**CHECKPOINT 1:** the VTA stores, searches, presents, and mints SD-JWT-VC
credentials end-to-end, with the no-wallet-enumeration invariant enforced
by a test. *Unblocks Phase 3.*

---

## Phases 2–6 — milestones (own PLAN pass before each starts)

- **Phase 2 — DTG catalog + VTC schema store + VIC** (this repo:
  `vtc-service`, `dtg-credentials`). Adopt `dtg-credentials`; port VMC/VEC
  onto DTG; build the `schemas` keyspace + registry (issues + accepts,
  JSON Schema + DTG binding, admin CRUD); add the InvitationCredential
  (VIC); validate issued credentials against their schema at issue time.
  *Checkpoint: each catalog type issues against its schema.*

- **Phase 3 — credential-exchange protocol** (this repo: `vta-sdk`,
  `vta-service`, `vtc-service`). The `credential-exchange/*` Trust Task
  family wrapping OID4VCI (offer/request/issue) + OID4VP (query/present) +
  DCQL; issuer, verifier, and holder sides; relayer≠holder +
  `sealed_transfer` for secret-bearing issuance. *Checkpoint: VTC↔VTA
  issue + query + present.*

- **Phase 4 — role-by-VC + verified-assertion cache + VP-based `/auth`**
  (this repo: `vti-common`, `vtc-service`). The `verified_assertions`
  keyspace + record (TTL + invalidation); `/auth/challenge` (DCQL) +
  `/auth` (verify VP → write assertion → mint a derived JWT); extractors
  read the assertion record, not the JWT role; revocation/role-change
  invalidates the record; ceremony Admit/Remint/Depart issue/revoke Role
  VCs + update the cache; ACL → derived index. *Checkpoint: admin proven
  by a held Role VC; revocation invalidates within the window.*

- **Phase 5 — join ceremony integration** (this repo: `vtc-service`).
  The "join" ceremony sends a DCQL query from the schema store's required
  evidence; the holder presents; the ceremony assembles Facts from the
  verified VP → `decide()` → `execute()`; allow → issue the
  MembershipCredential (+ Role VC) back via the exchange; deny → the
  decision-trace reason; refer → the moderator queue; request_more → a
  DCQL loop. *Checkpoint: the spec §12 flow end-to-end (allow + deny).*

- **Phase 6 — browser plugin UX** (browser plugin, `vta-mobile-core`).
  Digital Credentials API → OID4VP; plain-English consent (reuse the
  ceremony English renderer) + per-claim disclosure; the device-side
  holder-binding signature; invite→join progress UI. *Checkpoint: Alice
  completes invite→join in the plugin.*

---

## Checkpoints / review gates

Each phase is its own PR (or PR series) and ends at a checkpoint that
**verifies** the slice with a test, not a "looks right." Cross-repo gate:
a `affinidi-tdk-rs` format must be released (path/git dep wired into this
workspace) before the this-repo phase that consumes it merges.

```
0a ─gate─▶ 1 ─gate─▶ 2 ─gate─▶ 3 ─gate─▶ 4 ─gate─▶ 5 ─gate─▶ 6
0b ─(audited, additive, joins at the credential-format registry)─▶
```

---

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| BBS scheme correctness/audit (highest) | IRTF test vectors + external audit before real signing; isolated in `affinidi-bbs`; SD-JWT-VC carries the near-term path so 1–6 don't wait on it. |
| Cross-repo coupling stalls this-repo work | Front-load 0a; keep 1.1–1.3 format-agnostic so Track B starts immediately. |
| Privacy invariant regressions | Each phase carries the invariant tests (no enumeration, consent-before-disclosure, claim minimisation) as acceptance criteria, not afterthoughts. |
| Role-by-VC breaks the hot path | The verified-assertion cache keeps authz synchronous; Phase 4 ships the cache before flipping extractors off the JWT role. |
| Scope creep across 7 phases | Only 0a + 1 are task-level now; 2–6 get their own PLAN pass at their gate. |

---

## Immediate next actions

1. **Track A:** confirm the `affinidi-sd-jwt` crate home in
   `affinidi-tdk-rs`, then start Phase 0a task 0a.1.
2. **Track B (this repo):** start Phase 1 tasks **1.1–1.3** in parallel —
   they need no upstream format.
3. Park Phase 0b on the audited track; it joins later without blocking.

See `vti-credential-architecture-tasks.md` for the task checklist with
acceptance criteria, verification steps, and file targets.
