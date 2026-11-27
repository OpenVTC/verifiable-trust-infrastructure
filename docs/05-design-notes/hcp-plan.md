# The Human Context Protocol in the VTA: implementation plan

**Status:** plan, step 0 of 6. Nothing is built; this note and
[hcp.md](hcp.md) are step 0.
**Companion to:** [hcp.md](hcp.md) (the design: why, the model, the
decisions), [hcp-tasks.md](hcp-tasks.md) (the V0 checklist, generated from
§3) and [tasks/hcp-demo-plan.md](../../tasks/hcp-demo-plan.md) (the demo
week).
**Owner:** Brendan Miller, Alberto Leon
**Last updated:** 2026-11-26

This plan turns the design into runnable milestones, says what can run in
parallel, lists the risks, and fixes the check at each milestone boundary.
The milestones are aligned with the tiers of Keyring's agent-connect plan
(keyring-wallet PR 958, P0, P1 and P2): each tier gains an **HCP increment**
behind two flags, the VTA's `hcp` cargo feature and Keyring's flag in
`connected-agents`. With both off, each tier is exactly as it was. The Keyring
side, its screens and copy, is detailed in the Keyring companion plan
(keyring-wallet, branch `docs/agent-connect-plan-hcp`,
`docs/plans/agent-connect-plan/2026-11-25-bam.md`); this plan uses the same
milestone names and work-package ids.

---

## 1. Steps

Each step names the PR or branch it lands as. A code PR names the step it
completes and updates this note's `Status:` line in the same PR.

| # | Step | Lands as | Exit check |
|---|---|---|---|
| 0 | This note, [hcp.md](hcp.md), [hcp-tasks.md](hcp-tasks.md) and the demo plan | `docs(hcp)`, docs only, before any code PR | Maintainer has read the design |
| 1 | **V0**, the demo (with Keyring's P0 HCP increment) | A `feat/hcp-demo` branch on a fork, pinning the suite as frozen at X0. **Never merged to `main`**; any PR from it stays draft | §6, V0 |
| 2 | **V1** = A7 + H0 + H1 (with Keyring's P1 HCP increment) | On the suite's first release (out since 2026-11-27, §5): single-unit PRs in order `vti-specs-hcp` → `vta-hcp` → spine wiring → tests → docs, then H1 | §6, V1 |
| 3 | **V2** = H2 (with Keyring's P2 HCP increment): the First-Party claim | One PR per task group, then the conformance run | §6, V2 |
| 4 | **H3**: Delegated Authorization, VC Evidence, Memory Manager profiles | One PR per profile | §6, V3 |
| 5 | **H4**: Provider Interop through the OAuth sidecar | VTA-side internal API, then the sidecar crate and image | §6, V3 |
| 6 | **H5**: Agent Interop, MCP over Streamable HTTP from `vta-mcp` | `vta-mcp` PRs; nothing in the VTA | §6, V3 |

Order rationale. V0 proves the hardest path end to end, the person's approval
of a third party's grant on their phone and a revocation the client hears
about, on a branch that cannot leak a demo-week pin onto `main`. When this plan
was written the suite was unpublished; it is now published and released as
`draft` 0.1 (§5), so V0 pins the published bundles by digest, and a draft can
still change in place. Whether V0's units then go to `main` sooner, as V1's
single-unit PRs, is the maintainer's call; nothing in the suite now prevents
it. V1 starts
with HTTP parity because the HTTP Binding is what any conformance claim rests
on ([hcp.md](hcp.md) §1), and building it beside each handler is cheaper than
a retrofit. V2 completes the binding and makes the first real claim. V3's
three phases are independent of each other and of any Keyring tier; H4 is
last among the hard ones because it needs an external security review.

## 2. Milestones

Read the diagram top to bottom: each Keyring tier lines up with the VTI
milestone that carries its HCP increment, and the bottom row is the
conformance claim each milestone leaves the VTA able to make.

```text
 Keyring  P0 HCP increment  P0 rest (C9)    P1 HCP increment  P2 HCP increment  (no tier)
          (the demo)                        |                 |
          |                                 |                 |
 VTI      V0 -----------------------------> V1 -------------> V2 -------------> V3
          demo week, fork branch            A7 + H0 + H1      H2                H3 | H4 | H5
          |                                 |                 |                 |
 claim    aligned pilot                     aligned pilot     First-Party       + profiles,
          (no conformsTo)                   (no conformsTo)   package           Provider and
                                                                                Agent Interop
```

| Milestone | Keyring side (companion) | VTI side | Runnable demo | Conformance at the end |
|---|---|---|---|---|
| **V0** (P0 HCP increment) | Connect by QR and a typed number; approve with the HCP 6.1.6 checklist; a temporary 4-hour grant; purposes shown by their IRIs' descriptions; add a memory; revoke with the live notice state | X0–X5, A1–A6, A8, A9 | `agent-connect-p0-hcp`: the CLI shows a QR and a number → the person approves in Keyring ("For 4 hours") → the agent answers from context → the person adds "I'm vegetarian" and the next answer uses it → revoke: "was told at <time>", the CLI prints the notice, the next query is refused | Aligned pilot |
| **P0 rest** | C9: the HCP grant model on Keyring's base connect path (temporary by default, persistent as its own act, never pre-selected) | none | P0's exit gains two rows: the demo script passes with the flags on; with them off, P0 is unchanged | — |
| **V1** (P1 HCP increment) | C4 "What my agent saw", C5 "Answers on", C10 memories on HCP, C11 rooms with onward sharing, C12 the two connect paths merged, C13; plugin B5, B7–B9 | A7, then H0 (A10 HTTP parity first) and H1 | `agent-connect-p1` with HCP rows: the agent is added to a room with onward sharing elected, a share is reported and shown in "What my agent saw", an "Answers on" directive is applied by the plugin, Delete memory withdraws entries, and the same operation over HTTP returns the same result | Aligned pilot |
| **V2** (P2 HCP increment) | Each separable, with its own exit: C14 governance screens, C15 "Also delete what it remembered", C16; plugin B10 over the HTTP Binding | H2 | Per step: `agent-connect-p2-hcp-governance`, `agent-connect-p2-wipe`, `agent-connect-p2-first-party` (the conformance run passes and the claim is published on that instance) | **First-Party package** on one deployment |
| **V3** (after P2) | none; Keyring's "present to a third party" can use H4 once built | H3, H4, H5, each runnable alone | Per phase (§3.4) | + profiles; Provider Interop; Agent Interop |

## 3. Work packages

Ids follow the Keyring companion: **X** coordination, **A** VTI, **B** the
agent client, **C** Keyring, **D** the demo environment, **H** the VTI phases
after the demo. Task-level detail for V0 (acceptance, verify, files) is in
[hcp-tasks.md](hcp-tasks.md).

### 3.1 Coordination

| WP | Work | Milestone |
|---|---|---|
| X0 | **Freeze.** Re-check every snapshot the plan names (VTI `main`, the suite, Keyring, openvti-starter) and diff the cited VTI files; re-read any that moved. Tag the suite commit; build its registry and bundles; record digests and fixtures in a demo contract | V0 |
| X0b | **Skeleton commit.** Empty `vti-specs-hcp` (on the `vti-specs-vtn` precedent) and `vta-hcp` crates; workspace members with `[lints] workspace = true`; `Dockerfile.nitro` `COPY` lines; root `CLAUDE.md` crate-table rows via `check-docs.py --write`; `RELEASING.md` crate counts; `scripts/semver-report.sh` exclusions; the `hcp` feature (optional dependency, off by default) with a [feature-flags.md](../02-vta/feature-flags.md) row and a feature-combination CI step; keyspace names | V0 |
| X1 | **VTI specification drafts**, three separate texts ([hcp.md](hcp.md) §12): (a) Appendix F divergence entries; (b) the `VTI-HCP-*` change proposal; (c) the Appendix H change: each purpose's DTG registry IRI listed as canonical, the bare name kept as a deprecated alias mapped to the IRI before the exact comparison. Filed after the demo, before any VTI PR leaves draft | V0 (drafts), V1 (filed) |
| X2 | **Editor questions**: N1–N10 are now the suite's questions 44–52 and 16 in `specs/hcp/_shared/0.1/QUESTIONS.md` ([hcp.md](hcp.md) §12), beside 37, 46 and 56, which the suite lists as most important. Sent to the HCP editors with the working demo, not before; an answer changes the suite, and [hcp.md](hcp.md) follows it | V0 |
| X3 | **Docs with the code**: keep [hcp.md](hcp.md) and this note current; `vta-hcp/CLAUDE.md` (its invariants); the `vta-service/CLAUDE.md` integration-flow entry; `//!` module docs citing requirement ids | every step |
| X4 | **Merge gate and independent review**: the cheap required CI checks at every merge; the full pre-push list before the first full run; a review by someone given the diff and the HCP text, not our conclusions, that checks the requested testing and the coverage | V0 |
| X5 | **Purpose vocabulary** proposed to the Trust Over IP DTG registry (`trustoverip/dtgwg-vsc-registry`): definition format, validation, and the first draft entries, `task-execution/1` and `personalisation/1` under `https://registry.trustoverip.org/dtg/purpose/`, after a reuse check against the Personal Data Portability Protocol codes. The demo reads these IRIs from configuration and does not wait on review | V0 |
| X6 | V1 merge gate and independent review | V1 |
| X7 | First-Party claim paperwork; editor liaison | V2 |

### 3.2 VTI (V0)

| WP | Work | Depends on |
|---|---|---|
| A1 | **`vti-specs-hcp`**: pin the `hcp/*` tasks V0 uses (`hcp/grants/{request,revoke,revoked}`, `hcp/entries/{query,create}`, `hcp/audit/read`, `hcp/disclosures/summary`, all `0.1`) from the published registry with `trust-tasks -C vti-specs-hcp add` and `check`; commit `trust-tasks.toml`, the lock and the bundles together; framework specs (`trust-task-next-step`, `trust-task-discovery`) are not pinned here; the facade re-export and `schema_index` merge | X0b |
| A2 | **`vta-hcp` core**: the `HcpProvider` trait, `HcpCtx`, `HcpError` and a `StubHcp` with fixtures (the contract the other A packages build against); grant and entry stores; opaque hashed tokens; the per-request check returning `VerifiedGrant`; the `subject.id` secret through key custody; the keyspace checklist ([hcp.md](hcp.md) §10); orchestration in `vta-service/src/operations/hcp.rs` | A1 |
| A3 | **`hcp/grants/request` hold**: (`threadId`, `issuer`) match, another `issuer` on the thread `permissionDenied`, a changed payload `malformedRequest`; `hint.retryAfter` in seconds; the pending `task-consent/request` from a `remote_approval`-style producer with a bound approver and the HCP 6.1.6 items as effects of the published kinds ([hcp.md](hcp.md) §5.1); `parentThreadId` set to the held `threadId` on that request (`consent_request.rs` sets no thread member today); the hold as `trust-task-next-step`; an expired hold denied, never reopened, with ended threads remembered; registration at approval, the declared divergence from the suite's refusal of an unregistered `issuer` (question 52), recording the `issuer` VID for notices; the same `grantId` for an hour, with a new token; the token expiring with the grant (`tokenExpiresAt` = grant `expiresAt`) | A2, A8 |
| A4 | **`hcp/entries/query`** (at most the lesser of `maxEntries`, default 5, and 20; relevance order, `lexical`, recency breaking ties; grant-scoped `ref`; minimisation report; `useUntil` with the 1-hour cap) and **`hcp/entries/create`** (`person-declared` only; with no `accessToken`, the person's write through the enrolled admin DID) | A2 |
| A5 | **`hcp/grants/revoke` and the notice**: immediate, tombstone, exempt from the operation budget and the REST limiters by a code-level list; a repeat revoke succeeds with no second event or notice, an unknown `grantId` `permissionDenied`; a notice only to a client holding disclosed entries, at its registered VID; the `hcp/grants/revoked` schedule extends `PushReissuer`'s, re-issuing on every attempt (today it re-issues only past the acceptance window); fresh document per attempt, stable `noticeId`; at least 5 attempts over an hour, none after 24 hours; a non-retryable error abandons; the client's acknowledgement admitted with no ACL entry | A2 |
| A6 | **`hcp/audit/read` and `hcp/disclosures/summary`** (with the notice state Keyring polls: `notification` `delivered`, `abandoned` or `none`, and `usableUntil`); HCP events as `VtaOperation` dotted actions; audit before the state change, fail closed except on revoke | A2 |
| A8 | **Spine wiring**, by the Trust Task recipe: a `TASK_*` const per URI from the generated `TYPE_URI`; one `dispatch_table!` line per served URI with its class, under `#[cfg(feature = "hcp")]`, and each in `KNOWN_FEATURE_GATED_URIS`; `RETRY_SAFETY` rows (`grants/request` is `KeyedSecret`: it returns a token); policy-gate subject handling; a `checked!` conformance witness per served URI; the MCP guard risk class and the `vta-mcp` census; `error_code_census` witnesses; the token-bearing response out of the duplicate-execution record; the `hcp::is_context_client_task` admission hook; `hcp/*` refused over REST; a request proof (`authentication`) required on every `hcp/*` request; governance tasks and `hcp/entries/create` accepted with no `accessToken` only from the enrolled admin DID, any other issuer `permissionDenied`; `vta_call` refuses `hcp/*`. `hcp/grants/revoked` is sent by the VTA, so it gets a const but is never served. No census allowlist grows | A2 (on `StubHcp` first) |
| A9 | **Integration tests** in `vta-service/tests/it/hcp_demo.rs` through `MockVta` with the `transport-harness` feature, over TSP, real gates, no auth bypass: the happy path and the refusals (another VID's token, a revoked grant, a wrong purpose, REST, revoke under an exhausted budget, a decline and a timed-out hold, each followed by a resubmission that gets the same `permissionDenied` and no grant), each asserting the wire `code`, its typed error and its audit row; a `did:webvh` agent VID, not only `did:key`. Records a transcript the agent client's and Keyring's fakes are regenerated from | A3–A6, A8 |

A7 (`hcp/directives/set`) was moved to V1 with the Keyring screen that uses it,
so V0's discovery serves six `hcp/*` tasks and V1's seven.

### 3.3 Outside this repository (V0)

| WP | Where | Work |
|---|---|---|
| B1–B4, B6 | The agent client (`berkmancenter/vti-agent-connect`, TypeScript) | Own VID and mediator mailbox; TSP 1.0 through `@openvtc/trust-tasks-tsp` 0.2.0 or later (binding `tsp/0.3`; 0.1.x speaks only the Rev 2 draft and cannot reach the VTA); QR and number; the hold and resubmit over TSP, honouring `hint.retryAfter` and treating a next step never as the response; answers from retrieved context, printing purpose and `useUntil`; a mediator receive loop that acknowledges `hcp/grants/revoked`, de-duplicates on `noticeId`, purges and stops; tests against a fake VTA, including a duplicate notice |
| C0–C3, C6–C8 | keyring-wallet | The flag; an HCP client with `@openvtc/trust-tasks` (0.31.10 or later carries the suite) types as frozen at X0; governance tasks and `hcp/entries/create` with no `accessToken` (question 56), signed for `authentication`; scan, number and approve (the structured HCP 6.1.6 checklist over the request's effects, by the kinds in [hcp.md](hcp.md) §5.1; the consent request accepted only when its `parentThreadId` equals the scanned `threadId`); the agent list; disconnect revoking both the grant and any ACL entry; a new memory; revoke with the live notice state, polling `hcp/disclosures/summary`; jest; mockups |
| D1–D4 | openvti-starter, a demo variant | A VTA image built from the VTI branch with `hcp` added to its features, tagged by ref, never `latest`; `pins:verify` for it; the lab stack in MODE=tunnel; the runbook ([tasks/hcp-demo-plan.md](../../tasks/hcp-demo-plan.md)) |

### 3.4 After V0

**V1: A7 + H0 + H1.**
- **A10, HTTP parity, first:** `/v2/*` routes for the served operations behind
  an `hcp-http` feature, through `REST_EXCEPTIONS` with an auth extractor,
  OpenAPI wrappers and the snapshot committed; the per-IP limiter only on
  unauthenticated routes. Parity test: same handler, same result.
- **A7:** `hcp/directives/set`, delivered with query results; null and empty
  told apart.
- **H0, harden:** X1 filed; REST `hcp/*` with a required `issuer` proof; the
  full notice schedule and the abandonment alert (HCP 6.2.4); tombstones that
  survive a restore; a redaction census (no token in any retained store);
  the `hcp/*` tasks in `trust-task-discovery` and still no HCP discovery
  document, which needs an HCP binding in `conformsTo` (V2,
  [hcp.md](hcp.md) §9.4); management tokens replacing DID-proven
  management; the suite's first release and the Rust presence fix, both in
  `trust-tasks-rs` 0.42.0 and `trust-tasks-build` 0.3.0, adopted in one bump,
  with `trust-tasks-tsp` 0.42 refusing a TSP draft (`tsp/0.3`); SDK client methods and `pnm` commands with `--json`; held replies
  in `vta-sdk` (a `threadId` on every request, a `trust-task-next-step` never
  returned as the result, resubmission per its continuation) and a dedicated
  HCP tool in `vta-mcp` that keeps the token out of the model's context (HCP
  10.5; [hcp.md](hcp.md) §9.4), replacing the V0 refusal in `vta_call`; a fuzz target
  for the admission parser; the demo branch rebased onto `main` with a map of
  old to new commits.
- **H1, context plane:** `hcp/entries/{get,revise,withdraw}`,
  `hcp/grants/{read-own,relinquish}`, `hcp/shares/report` (`context.shared`)
  on both carriages; version history; purpose IRIs from the registry once
  reviewed; persistent grants as a separate act; a notice service on the
  agent's DID; Go-client interoperability.
- Outside: C4, C5, C7 (its P1 part), C10–C13; B5, B7–B9; D5 (image and lab for
  rooms); X6.

**V2: H2.** `hcp/grants/list`, `hcp/rules/*`, `hcp/directives/{list,remove}`,
`hcp/export`, `hcp/import`,
`hcp/entries/{hard-delete,confirm,set-categories,restrict-purposes}`; the
full HTTP Binding (HCP 9.5–9.9); the HCP discovery document (HCP 19), bound
to the VTA's VID as every `hcp/*` specification's "Parties" rule requires;
signed audit
checkpoints; the HCP 20.2 test hook on lab builds only; the conformance run;
the First-Party claim published on one lab or fleet instance whose operator
runs Keyring and the agent client. Outside: C14–C16, B10, D6, X7.

**V3.**

| Phase | Scope | Runnable demo | Conformance at the end |
|---|---|---|---|
| H3, profiles | Delegated Authorization (an HCP capability, not an ACL entry); VC Evidence (`eddsa-rdfc-2022`, pinned contexts, W3C vectors, status); Memory Manager (the VTA then accepts `model-inferred`) | A guardian and a child; credentials as evidence; agent-inferred memories | + the three profiles |
| H4, Provider Interop | The OAuth sidecar ([hcp.md](hcp.md) §9): authorize with PKCE, PAR and RAR, token, metadata, registration, device flow, RFC 7009; the VTA's internal API; a separate image and deployment variant; external security review | Another organisation's agent connects through OAuth | Provider Interop; First-Party dropped |
| H5, Agent Interop | MCP over Streamable HTTP from `vta-mcp`, MCP authorization onto HCP 13.5 | Any MCP host, without the plugin | Agent Interop |

## 4. What runs in parallel

Read the V0 map left to right: the VTI track (top) is the critical path, and
the agent client, Keyring and environment tracks run beside it against fakes
until A3 and D3 are live.

```text
 X0 -> X0b -> A1 -> A2 --+--> A8 spine wiring ----------+
              |          +--> A3 hold (wired by A8) ----+--> A9 tests --> X4 gate --+
              |          +--> A4 query, create ---------|                           |
              |          +--> A5 revoke, notice --------|                           |
              |          +--> A6 audit, summary --------+                           |
              |          +--> D1 image --> D2 verify --> D3 lab, MODE=tunnel -------+
              |                                                                     |
              +-------> C0 Keyring client --> C1 approve (A3 live) -----------------+--> first run
                                         +--> C2, C3, C6 --> C7 jest ---------------+   -> rehearsal
 B1 QR, number --> B2 hold --> B3 answers, B4 notice --> B6 tests ------------------+   -> demo
 X1, X2, X5 run beside everything; nothing waits on them
```

- **Critical path:** X0 → X0b → A1 → A2 → A3 → C1 live → D3 → X4 → the first
  full run → on-device test → rehearsal.
- **A8 starts on `StubHcp`**, beside A2 → A3. If the stub slips, A8 joins the
  critical path.
- **A4, A5 and A6** need only A2's frozen trait, so they run in parallel with
  A3. A5, B4 and C6 (the notice path) are near-critical.
- **Interface contracts** let the tracks start before the VTA is live: the
  suite as frozen at X0, with its fixtures; A2's trait, `StubHcp` and fixtures;
  the keyspace names (X0b); the approval document layout (A3 with C1); the QR
  and number format (B1 with C1); the fakes for the agent client and Keyring,
  regenerated only from A9's transcript; the environment file (D3).

**V1.** The critical path is the re-pin to the suite's first release → A10 →
H1's entries plane → C10, C11 and B8 live → the P1 lab run. A7 goes first in
its track so C5 and B5 have a live target.

**V2.** The critical path is H2's governance tasks → the full HTTP Binding →
the conformance run on the First-Party deployment (D6) → the claim. Keyring's
P2 items are separable and ship on their own exits.

## 5. Cross-repository dependencies

| Dependency | Where | What VTI needs | When |
|---|---|---|---|
| The `hcp/*` suite | dtgwg-trust-tasks-tf `main`: merged as #1380 (28 `hcp/*` tasks at `0.1`, `draft`, framework `0.6.0`), #1381 (declared unchecked rules) and #1382 (demos in four languages) | The suite frozen at X0 for V0: the published bundles pinned by digest, since a draft can change in place | X0 |
| The suite's first release | **Done 2026-11-27**: published at trusttasks.org; `trust-tasks-rs` 0.42.0, `trust-tasks-build` 0.3.0, `@openvtc/trust-tasks` 0.31.10 | Digests from the published registry. The gate "nothing HCP merges to VTI `main` before it" is met. VTI pins `trust-tasks-*` 0.41 and `trust-tasks-build` 0.2.2 today, so adopting it is a 0.41 → 0.42 bump across every `trust-tasks-*` dependency, a workspace event | V1 (H0) |
| The Rust presence fix | Released in the same release (#1385, `trust-tasks-rs` 0.42.0 and `trust-tasks-build` 0.3.0) | Optional and nullable members keep "empty", "absent" and "null" apart; field types change in every `vti-specs-*` crate, so the 0.42 adoption is its own `!` PR | V1 (H0), with the suite's release |
| TSP 1.0 and binding `tsp/0.3` | Released: `trust-tasks-tsp` 0.42.0 (refuses a TSP draft as `UnsupportedTspVersion`), `@openvtc/trust-tasks-tsp` 0.2.0 | The VTA already speaks TSP 1.0 (`affinidi-tsp` 0.5); the agent client needs the TypeScript 0.2.0 package to reach it at all | X0 for the agent client; the 0.42 adoption for the VTA |
| Go 1.24 for the Go library | dtgwg-trust-tasks-tf; released in the Go core `v0.14.0` | Required-nullable members no longer omitted; `trusttasks.Nullable` (absent, null and a value kept apart, #1376) is merged but not yet in a release; affects the Go interop client, not VTI | Before H1's Go interop test |
| The TypeScript library | dtgwg-trust-tasks-tf (`@openvtc/trust-tasks` 0.31.10 or later) | Keyring and the agent client use the suite as frozen at X0, like A1 | X0 |
| Keyring's agent-connect plan | keyring-wallet (PR 958 and its HCP companion) | The C track, the screens and the copy; the same milestone names and ids | every milestone |
| The agent client | `berkmancenter/vti-agent-connect` (a temporary repository until it exists) | The B track | V0 onward |
| Purpose IRIs | `trustoverip/dtgwg-vsc-registry` | The draft entries at `https://registry.trustoverip.org/dtg/purpose/<name>/<n>` reviewed; until then the drafts are used. The directive action URI is not in the registry: it is on a Keyring-controlled domain ([hcp.md](hcp.md) decision 16). The VTA reads both from configuration | X5 in V0; reviewed IRIs in H1 |
| Images | openvti-starter | A VTA image with `hcp`, built and pinned through its tooling, never by hand; an `oauth-sidecar` image and deployment variant in H4 | D1; H4 |
| Divergences and VTI changes | dtgwg-vti-spec | Appendix F entries, the `VTI-HCP-*` proposal and the Appendix H purpose-IRI change (X1) | Filed before any VTI PR leaves draft |
| HCP readings | The HCP editors | Answers to the suite's questions, first 37, 46 and 56, and 44–52 and 16 (this work's N1–N10); the HCP-side status of the Trust Task carriage | Sent with the demo |

## 6. Checks at each milestone boundary

- **End of step 0:** `scripts/check-docs.py` passes; the maintainer has read
  [hcp.md](hcp.md).
- **End of V0:**
  - the demo script ([tasks/hcp-demo-plan.md](../../tasks/hcp-demo-plan.md))
    passes end to end on the tunnelled lab, twice;
  - with the `hcp` feature and Keyring's flag off, the VTA and Keyring behave
    exactly as before (clippy `-D warnings` and the tests with and without
    `--features hcp`; discovery lists no `hcp/*` task without the feature);
  - A9 green; the full pre-push list green, with any known false failure
    recorded as such; no census allowlist grown;
  - the independent review's findings fixed or listed;
  - X1's two drafts and X2's questions written.
- **End of V1:** the suite's first release adopted, so nothing pins a local
  registry; the parity test green for every served operation over both
  carriages; the redaction census and the admission fuzz target in CI; X1
  filed; the P1 lab run passes; the single-unit PR sequence merged to `main`.
- **End of V2:** the conformance suite passes against the First-Party
  deployment; the claim is published there and nowhere else; the HCP 20.2 test
  hook exists only on lab builds.
- **End of each V3 phase:** H3: each profile's conformance checks pass. H4:
  the external security review and penetration test closed; a test proving the
  VTA works with the sidecar absent; the internal API's operations each
  authorized and audited. H5: an MCP host completes the HCP flow over
  Streamable HTTP.

## 7. Risks

| Risk | Likelihood / impact | Mitigation |
|---|---|---|
| Review capacity in the demo week, a holiday week | High / high | Review A2, A3, A5, A8 and C1 first, the security paths; light passes elsewhere, before anything is pushed |
| The phone cannot reach the lab: the tunnel's phone leg is untested, and a restart needs relinking | Medium / high | MODE=tunnel; a phone-leg smoke test in D3; two rehearsals; a recorded video |
| Keyring is not woken in the background | Certain / medium | Foreground only: the app is open at approval; Keyring polls `hcp/disclosures/summary` for the notice state |
| The agent client's mediator receive loop misses the notice | Medium / medium | Reuse openvti-starter's mediator session patterns; de-duplicate on `noticeId`; admit the acknowledgement (A5, A8); a duplicate-notice test |
| `trust-tasks-build` fails on an `hcp/*` bundle | Low-medium / high | A1 checks it first; a `[patch]` to the repository's builder on the fork branch only |
| VTI `main` and openvti-starter's pinned VTA and mediator have drifted | Medium / medium | A dry-run image from `main` early in the week; a tunnel-mode smoke test; fall back to the starter's pinned ref only if the mediator fails |
| The suite changes under the demo | Medium / low (released, but `draft`, so it may change in place) | Pin by digest at X0; re-pin only by agreement |
| A token leaks into a store or a log | Medium / high | Redaction in A8; REST refused; a census in H0 |
| No-ACL admission widens the VTA's surface | Medium / medium | Only the agent-sent `hcp/*` URIs; each needs TSP sender binding and an `issuer` proof; refusal tests in A9 |
| Consent-screen spoofing | Low / high | Keyring renders only the VTA-signed request, for the VID and `threadId` it scanned |
| HCP never recognises the Trust Task carriage | Medium / medium | The claim rests on the HTTP Binding |
| OAuth scope and library choice (H4) | High / high | The sidecar keeps the VTA small; a library survey first; external review |
| The audit trail is unanchored under a hosted operator | Medium / medium | Signed checkpoints in V2 |

## 8. What this plan does not decide

- **The OAuth sidecar's implementation**: our own small binary, or an embedded
  mature authorization server. A Rust library survey decides it before H4
  (maturity, PAR and RAR, client ID metadata documents, the device flow, the
  RFC 9700 posture).
- **The placement of the other non-core surfaces** ([hcp.md](hcp.md) §9.4):
  recommendations, not decisions.
- **Whether the directive action URI moves to a shared registry later.** It
  stays on a Keyring-controlled domain until the HCP editors answer question 51 (N8) and the
  registry's editors decide whether acts in another's name get a vocabulary.
- **Exact wire members** beyond what the `hcp/*` specifications fix.
- **`vta/memory/*` and the HCP entry store.** They stay side by side in V0,
  with nothing copied between them; whether a bridge or a migration follows is
  deferred ([hcp.md](hcp.md) §6).
- **Narrowing at approval.** The suite allows a narrower grant than asked;
  V0 approves as asked and narrows with governance tasks; a decision that
  carries choices would be a new `task-consent/decision` version and is not
  planned ([hcp.md](hcp.md) §4.1).
