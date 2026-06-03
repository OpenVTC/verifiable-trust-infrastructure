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
| **`affinidi-tdk-rs`** (external; published crates) | the credential *crypto + formats*: SD-JWT-VC, BBS+ (`affinidi-bbs`), the `bbs-2023` Data Integrity cryptosuite, BLS12-381 keys. |
| **`verifiable-trust-infrastructure`** (this workspace) | everything that *uses* credentials: the VTA store, VTC schema store + issuer, the exchange protocol, role-by-VC + the verified-assertion cache, the ceremony integration, plugin UX. |

**Coordination rule:** a this-repo phase that consumes a new format
cannot start until that format is available as a published/path/git dep
from `affinidi-tdk-rs`. The plan front-loads the format work (Phase 0a)
and keeps the format-agnostic this-repo work (the store's model/index)
able to start in parallel.

---

## Dependency graph

```
                 ┌─────────────────────────── (affinidi-tdk-rs) ───────────────────────────┐
   Phase 0a  SD-JWT-VC ──────────────┐
   Phase 0b  BBS foundation ─────────┤  (additive: a new format + cryptosuite; never blocks 1–6)
                                     │
                 └─────────────────── │ ───────── (verifiable-trust-infrastructure) ────────┘
                                     ▼
   Phase 1   VTA credential store    │   1.1–1.3 (model / receive / search) are FORMAT-AGNOSTIC →
             ────────────────────────┘   can start NOW, parallel to 0a.
                                         1.4–1.6 (present / mint / status) need a format (0a).
                                     ▼
   Phase 2   DTC catalog + VTC schema store + VIC
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
- **Track A (affinidi-tdk-rs):** Phase 0a (SD-JWT-VC). Phase 0b (BBS) on
  its own audited track.
- **Track B (this repo):** Phase 1 tasks **1.1–1.3** — the
  `StoredCredential` model, the `vault` keyspace + index, and local
  DCQL-shaped search — are format-agnostic (they index opaque credential
  bodies + metadata) and don't need 0a. They converge with 0a at task 1.4
  (present), which needs a real format verifier/presenter.

---

## Vertical slicing principle

Every task is **one complete path**, not a horizontal layer. For SD-JWT
that means "issue → disclose → verify a credential with N claims" as a
single slice, not "all issuance, then all verification." For the store it
means "store + index + retrieve one credential end-to-end" before adding
search, then present.

---

## Phase 0a — SD-JWT-VC  (repo: `affinidi-tdk-rs`)

**Goal:** a selective-disclosure credential format with no new curve —
runs on the existing Ed25519/JOSE — so the this-repo phases can build on
it immediately. **Home:** a new `affinidi-sd-jwt` crate (mirrors the
`affinidi-bbs` isolation decision; keeps the disclosure machinery out of
the base crypto crate). *Final home is an `affinidi-tdk-rs` repo call.*

Slices (detail in the tasks doc): SD-JWT core round-trip → selective
disclosure → key binding (`kb-jwt`) → the SD-JWT-VC profile (`vct`/`cnf`/
`status`) → IETF interop fixtures → the public `issue/present/verify` API.

**CHECKPOINT 0a:** `affinidi-sd-jwt` exposes `issue` / `present` (select
+ bind) / `verify` (returns the disclosed claim set + holder DID), green
against the IETF SD-JWT examples. *This is the gate that unblocks Phase 1
present/mint and Phase 3.*

---

## Phase 0b — BBS foundation  (repo: `affinidi-tdk-rs`; gated, parallel, audited)

**Goal:** unlinkable claim-level selective disclosure as a W3C Data
Integrity cryptosuite. **Net-new** — the dependency tree has no BLS today.

Milestones: adopt `arkworks`/`ark-bls12-381` → BLS12-381 G2 keygen +
`affinidi-crypto` trait impls (`#bbs-key-0`) → `bbs-2023` sign/verify vs
IRTF test vectors → `bbs-2023` proofgen/proofverify (selective disclosure)
vs IRTF vectors → the `bbs-2023` Data Integrity cryptosuite in
`affinidi-data-integrity` → Ed25519 holder binding → **security review**.

**CHECKPOINT 0b:** IRTF test vectors pass + end-to-end issue/disclose/
verify; **audited before any real signing.** Additive — adding BBS+ to
the credential layer is a new format registration, so 0b never blocks 0a
or 1–6.

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

- **Phase 2 — DTC catalog + VTC schema store + VIC** (this repo:
  `vtc-service`, `dtg-credentials`). Adopt `dtg-credentials`; port VMC/VEC
  onto DTC; build the `schemas` keyspace + registry (issues + accepts,
  JSON Schema + DTC binding, admin CRUD); add the InvitationCredential
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
