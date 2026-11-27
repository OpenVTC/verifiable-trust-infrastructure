# The Human Context Protocol in the VTA: V0 task checklist

**Status:** not started; 0 of 15 V0 tasks done.
**Companion to:** [hcp.md](hcp.md) (the design) and
[hcp-plan.md](hcp-plan.md) (the plan this is generated from). The demo week
is [tasks/hcp-demo-plan.md](../../tasks/hcp-demo-plan.md).
**Owner:** Brendan Miller, Alberto Leon
**Last updated:** 2026-11-26

V0 is task-level here; V1, V2 and V3 are milestone-level in
[hcp-plan.md](hcp-plan.md) §3.4 and get their own pass when they start. Only
the VTI tasks and the coordination tasks V0's exit needs are listed; the agent
client, Keyring and environment tracks are checklists in their own
repositories.

Each task: **Acceptance** (true when done) · **Verify** (the evidence) ·
**Files** (where the change lands) · **Deps**. Every cargo command takes
`--locked`. Tests are plain `assert!`s with sentence names carrying a
requirement prefix (`vti_trn_029_…`, `hcp_6_2_3_…`); every refusal test
asserts the wire `code`, the typed error and the audit row. No census passes
by raising a count or growing an allowlist.

---

## Coordination

- [ ] **X0 — Freeze.**
  - Acceptance: every snapshot the plan names is re-checked and recorded; the
    cited VTI files are diffed against the snapshot the design read, and any
    that moved are re-read; the dtgwg-trust-tasks-tf `main` commit the suite
    is taken from is recorded (the suite is published and released, but
    `draft`, so it may change in place); the published registry lists the
    `hcp/*` tasks V0 pins at `0.1` and every fixture validates.
  - Verify: the demo contract records the heads, bundle digests and fixtures.
  - Deps: none.

- [ ] **X0b — Skeleton commit.**
  - Acceptance: empty `vti-specs-hcp` and `vta-hcp` crates (version `0.1.0`)
    are workspace members with `[lints] workspace = true`; `Dockerfile.nitro`
    copies them; the root `CLAUDE.md` crate table and `RELEASING.md` counts
    match; `scripts/semver-report.sh` and the machete ignores updated; the
    `hcp` feature is an optional dependency, off by default, with a
    [feature-flags.md](../02-vta/feature-flags.md) row and a
    feature-combination CI step; the keyspace names are declared.
  - Verify: `cargo clippy -p vta-service --all-targets --locked -- -D warnings`
    with and without `--features hcp`; `python3 scripts/check-docs.py`;
    `scripts/check-workspace-lints.py`;
    `scripts/check-nitro-copies-every-member.py`;
    `cargo machete --with-metadata`.
  - Files: `Cargo.toml`, `vti-specs-hcp/`, `vta-hcp/`,
    `vta-service/Cargo.toml`, `vta-keyspaces/src/lib.rs`, `Dockerfile.nitro`,
    `CLAUDE.md`, `RELEASING.md`, `scripts/semver-report.sh`,
    `docs/02-vta/feature-flags.md`, the CI workflow.
  - Deps: X0.

- [ ] **X1 — VTI specification drafts.**
  - Acceptance: three separate texts are drafted ([hcp.md](hcp.md) §12): the
    Appendix F divergence entries; the `VTI-HCP-*` change proposal; and the
    Appendix H change listing each purpose's DTG registry IRI as canonical,
    with the bare name as a deprecated alias mapped to the IRI before the
    exact comparison (VTI-ACL-109). None is filed in V0.
  - Verify: the three drafts are linked from the demo contract.
  - Deps: none; final text after A9.

- [ ] **X2 — Editor questions.**
  - Acceptance: N1–N10 are already in the suite's
    `specs/hcp/_shared/0.1/QUESTIONS.md` as questions 44–52 and 16
    ([hcp.md](hcp.md) §12), each with the HCP section it reads and the
    assumption the suite takes; the demo's evidence is attached to them and to
    37, 46 and 56; they are sent with the working demo, not before.
  - Verify: the questions are linked from the demo contract.
  - Deps: none.

- [ ] **X5 — Purpose vocabulary.**
  - Acceptance: the definition format and the draft entries
    `task-execution/1` and `personalisation/1` are proposed to
    `trustoverip/dtgwg-vsc-registry`; the VTA's configuration names those
    IRIs, so a rename in review is a configuration change only.
  - Verify: the registry proposal's own checks pass; A4's fixtures use the
    configured IRIs.
  - Deps: none; the demo does not wait on review.

## VTI

- [ ] **A1 — Pin the suite in `vti-specs-hcp`.**
  - Acceptance: the pinned bundles (`hcp/grants/{request,revoke,revoked}`,
    `hcp/entries/{query,create}`, `hcp/audit/read`, `hcp/disclosures/summary`,
    all `0.1`) are byte-identical to the published registry's and their
    digests equal the contract's; the lock's `registry` line reads
    `https://trusttasks.org`; framework specs are not pinned here;
    `trust-tasks-build` generates every pinned task (checked first on
    VTI's 0.2.2 pin; if it cannot, the 0.3.0 adoption of
    [hcp-plan.md](hcp-plan.md) §5 comes first); the generated tables of
    the `vti-specs-*` crates stay disjoint.
  - Verify: `trust-tasks -C vti-specs-hcp check`;
    `cargo nextest run -p vti-specs --locked`.
  - Files: `vti-specs-hcp/` (`trust-tasks.toml`, `trust-tasks.lock`, bundles,
    `build.rs`), `vti-specs/src/lib.rs`.
  - Deps: X0b.

- [ ] **A2 — `vta-hcp` core, trait and stub.**
  - Acceptance: `HcpProvider`, `HcpCtx` and `HcpError` (`#[non_exhaustive]`,
    mapped through `reject_declared` to declared codes only) are frozen and
    `StubHcp` answers every fixture; revoked, expired and unknown tokens give
    `hcp:invalidToken`; a request outside the grant (wrong category or
    purpose) gives `permissionDenied` with one fixed message; a wrong-VID
    token gives a `permissionDenied` that reveals nothing else; a
    token-carrying request with no proof is refused; no
    `scope-denied` or `invalid-token` is ever sent on this wire, and
    `hcp:invalidToken` carries the meaning and `retryable: false` of the
    suite's `CONVENTIONS.md` §1; `tokenExpiresAt` equals the grant's
    `expiresAt`; `VerifiedGrant` can be built
    only by the per-request check; tokens are `Zeroizing` with a redacting
    `Debug`; the `subject.id` secret is reached only through key custody;
    `vta-hcp` does not depend on `vta-service`; a backup round trip keeps the
    tombstones and drops the token hashes.
  - Verify: `cargo nextest run -p vta-hcp --locked`;
    `cargo clippy -p vta-hcp --all-targets --locked -- -D warnings`;
    `secret_debug_census` and `no_bare_keyspace_literals` green.
  - Files: `vta-hcp/src/`, `vta-service/src/operations/hcp.rs`,
    `vta-service/src/server.rs` (keyspaces and `AppState`).
  - Deps: A1.

- [ ] **A3 — `hcp/grants/request` hold.**
  - Acceptance: a held request answers `trust-task-next-step` with
    `continuation: resubmit` and `hint.retryAfter` in whole seconds, never an
    error; a document on the thread from another `issuer` gets
    `permissionDenied` and leaves the hold unchanged; a resubmission with a
    different payload gets `malformedRequest`; the pending
    `task-consent/request` is bound to the request's digest and to the admin
    DID, with the HCP 6.1.6 items as effects of the kinds published in
    [hcp.md](hcp.md) §5.1 (or a purpose choice where none was named), and with
    `parentThreadId` equal to the held request's `threadId`; approval gives a
    grant and a token, both expiring 4 hours later; a resubmission within an
    hour gives the same `grantId`, a newly minted token under it and no
    second `grant.issued`, and stores no token; after the hour, or once the
    grant is revoked, `permissionDenied`; a hold not approved in 300
    seconds is denied (VTA policy), and the next resubmission on that thread
    gets the same `permissionDenied` as a decline and an unknown person, with
    the thread never reopened; the client registration is recorded at
    approval, with the `issuer` VID as its notice VID (the declared
    divergence from the suite's refusal of an unregistered `issuer`, question
    52).
  - Verify: `cargo nextest run -p vta-hcp --locked`; A9's hold cases.
  - Files: `vta-hcp/src/request.rs`; hooks in
    `vta-service/src/trust_tasks/hcp.rs` (through A8).
  - Deps: A2, A8.

- [ ] **A4 — `hcp/entries/query` and `hcp/entries/create`.**
  - Acceptance: a created `person-declared` entry appears in the next query;
    a `model-inferred` create is refused; a create with no `accessToken` is
    accepted only from the enrolled admin DID; a query returns at most the
    lesser of `maxEntries` (default 5) and 20, in relevance order, with
    `minimization.method` `lexical`; `ref` differs per grant; `useUntil` is
    at most an hour for a client with no notification endpoint.
  - Verify: `cargo nextest run -p vta-hcp --locked`.
  - Files: `vta-hcp/src/{entries,query,refs}.rs`.
  - Deps: A2.

- [ ] **A5 — `hcp/grants/revoke` and the notice.**
  - Acceptance: revoke succeeds under an exhausted operation budget (the
    exemption is a code-level URI list with a census); attempts carry
    distinct `id` and `issuedAt` and the same `noticeId`; the client's
    acknowledgement, from a sender with no ACL entry, stops the retries and
    records `revocation.notified`; a mediator handoff or a TSP delivery
    receipt alone does not; a non-retryable error abandons; nothing is sent
    after 24 hours; a client that holds no disclosed entry is not notified;
    revoking a revoked grant succeeds with no second event or notice, and an
    unknown `grantId` gets `permissionDenied`; the schedule extends `PushReissuer`'s, with no
    second retry loop.
  - Verify: `cargo nextest run -p vta-hcp --locked`; A9's revoke cases.
  - Files: `vta-hcp/src/{revoke,notify}.rs`; the exempt-URI list in
    `vta-service/src/trust_tasks/mod.rs` (through A8).
  - Deps: A2.

- [ ] **A6 — `hcp/audit/read`, `hcp/disclosures/summary`, the event vocabulary.**
  - Acceptance: each demo step leaves its HCP event as a `VtaOperation`
    dotted action; every refusal leaves a row; a failed audit write refuses
    `hcp/entries/create` and still lets `hcp/grants/revoke` succeed; a
    wrong-VID refusal logs `security_alert = true`; the summary carries the
    notice state; a Context Client is refused both tasks; `audit/verify` still
    passes.
  - Verify: `cargo nextest run -p vta-hcp --locked`;
    `audit_coverage::every_consequential_task_records_an_audit_entry` green.
  - Files: `vta-hcp/src/{audit,disclosures}.rs`; `vta-audit/src/event.rs`
    only if an action helper is needed.
  - Deps: A2.

- [ ] **A8 — Spine wiring.**
  - Acceptance: with the feature, discovery lists the six served `hcp/*`
    tasks, and without it none; `hcp/grants/revoked` has a `TASK_*` const and
    is not served; `hcp/*` over REST is refused; a missing proof is refused;
    the agent-sent tasks are admitted with no ACL entry only through
    `hcp::is_context_client_task`, after an ACL refusal, with zero authority;
    governance tasks and `hcp/entries/create` from Keyring need the admin
    role through `act_scope()` and carry no `accessToken`, and one whose
    proven `issuer` is not the enrolled admin DID is refused
    `permissionDenied`; `vta_call` refuses `hcp/*`; no token
    appears in the accepted-document store, the idempotency cache, the
    duplicate-execution record or a log (a new census asserts it);
    `spec_pin_census`, `every_uri_is_classified`,
    `every_public_task_is_proof_optional_and_read_only`, `error_code_census`,
    `response_record_census` and `payload_type_census` green, no allowlist
    grown.
  - Verify: `cargo nextest run -p vta-service --features hcp --locked` and the
    same without `hcp`; `cargo nextest run -p vta-sdk -p vta-mcp
    -p vti-mcp-common --locked`.
  - Files: `vta-service/src/trust_tasks/{mod.rs,hcp.rs,conformance.rs}`,
    `vta-service/src/trust_tasks/policy_gate.rs`,
    `vta-service/src/messaging/auth.rs`,
    `vta-sdk/src/{trust_tasks.rs,retry_safety.rs}`,
    `vti-mcp-common/src/guard.rs`, `vta-mcp/src/census.rs`,
    `vta-service/tests/it/main.rs`.
  - Deps: A2 (on `StubHcp` first).

- [ ] **A9 — Integration tests.**
  - Acceptance: one `hcp_demo` module in the single `it` binary, file-level
    `#![cfg(feature = "hcp")]`, through `MockVta` with the `transport-harness` feature
    over TSP with real gates; the happy path and each refusal (another VID's
    token, a revoked grant, a wrong purpose, REST, revoke under an exhausted
    budget, a decline and a timed-out hold, each followed by a resubmission
    that gets `permissionDenied` and no grant) pass; the agent VID is a `did:webvh`; a transcript is recorded for
    the agent client's and Keyring's fakes. A failure seen only under load is
    re-run alone before it is called a regression.
  - Verify: `cargo test -p vta-service --features hcp --test it --locked --
    hcp_demo::`.
  - Files: `vta-service/tests/it/hcp_demo.rs`.
  - Deps: A3–A6, A8.

## Docs and the gate

- [ ] **X3 — Docs with the code.**
  - Acceptance: [hcp.md](hcp.md) names where each invariant of A2–A8 is
    held; `vta-hcp/CLAUDE.md` lists them; `vta-service/CLAUDE.md` has the
    integration-flow entry; `//!` module docs cite requirement ids; no local
    or working-note paths in any tracked file.
  - Verify: `python3 scripts/check-docs.py`.
  - Deps: X0b; final text after A9.

- [ ] **X4 — Merge gate and independent review.**
  - Acceptance: the cheap required checks at every merge (`cargo fmt --all --
    --check`, `check-docs.py`, clippy `-D warnings` with and without `hcp`,
    `cargo deny check`, `scripts/check-authz-context-types.sh`,
    `cargo metadata --locked`, the lockfile checks); the full pre-push list at
    A9 and before the first full run, with known false failures recorded as
    such; every commit signed and signed off; the review findings fixed or
    listed.
  - Verify: the gate log in the demo contract.
  - Deps: A9.

- [ ] **CHECKPOINT V0** — the checks in [hcp-plan.md](hcp-plan.md) §6, "End of
  V0", all pass. *Gate: unblocks V1, starting with A10.*
