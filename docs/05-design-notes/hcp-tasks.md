# The Human Context Protocol in the VTA: V0 task checklist

**Status:** not started; 0 of 12 V0 tasks done.
**Companion to:** [hcp.md](hcp.md) (the design) and
[hcp-plan.md](hcp-plan.md) (the plan this is generated from). The demo week
is [tasks/hcp-demo-plan.md](../../tasks/hcp-demo-plan.md).
**Owner:** Brendan Miller, Alberto Leon
**Last updated:** 2026-11-25

V0 is task-level here; V1, V2 and V3 are milestone-level in
[hcp-plan.md](hcp-plan.md) §3.4 and get their own pass when they start. Only
the VTI tasks are listed; the agent client, Keyring and environment tracks are
checklists in their own repositories.

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
    that moved are re-read; the suite commit is tagged; the local registry
    lists the `hcp/*` tasks V0 pins and every fixture validates.
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

## VTI

- [ ] **A1 — Pin the suite in `vti-specs-hcp`.**
  - Acceptance: the pinned bundles are byte-identical to the local registry's
    and their digests equal the contract's; the lock's `registry` line reads
    `https://trusttasks.org`; framework specs are not pinned here;
    `trust-tasks-build` generates every pinned task; the generated tables of
    the `vti-specs-*` crates stay disjoint.
  - Verify: `trust-tasks -C vti-specs-hcp check`;
    `cargo nextest run -p vti-specs --locked`.
  - Files: `vti-specs-hcp/` (`trust-tasks.toml`, `trust-tasks.lock`, bundles,
    `build.rs`), `vti-specs/src/lib.rs`.
  - Deps: X0b.

- [ ] **A2 — `vta-hcp` core, trait and stub.**
  - Acceptance: `HcpProvider`, `HcpCtx` and `HcpError` (`#[non_exhaustive]`,
    mapped through `reject_declared` to declared codes only) are frozen and
    `StubHcp` answers every fixture; revoked, expired, wrong-purpose and
    unknown tokens give the same `scope-denied`; a wrong-VID token gives a
    `permissionDenied` that reveals nothing else; `VerifiedGrant` can be built
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
    `continuation: resubmit`, never an error; the pending
    `task-consent/request` is bound to the request's digest and to the admin
    DID, with the HCP 6.1.6 items as effects (or a purpose choice where none
    was named); approval gives a grant and a token, expiring 4 hours later;
    a replay within an hour gives the same `grantId` and stores no token; a
    hold not approved in 300 seconds ends; a decline answers
    `permissionDenied`; the client registration is recorded at approval.
  - Verify: `cargo nextest run -p vta-hcp --locked`; A9's hold cases.
  - Files: `vta-hcp/src/request.rs`; hooks in
    `vta-service/src/trust_tasks/hcp.rs` (through A8).
  - Deps: A2, A8.

- [ ] **A4 — `hcp/entries/query` and `hcp/entries/create`.**
  - Acceptance: a created `person-declared` entry appears in the next query;
    a `model-inferred` create is refused; a query returns at most 20 in the
    declared order; `ref` differs per grant; `useUntil` is at most an hour
    for a client with no notification endpoint.
  - Verify: `cargo nextest run -p vta-hcp --locked`.
  - Files: `vta-hcp/src/{entries,query,refs}.rs`.
  - Deps: A2.

- [ ] **A5 — `hcp/grants/revoke` and the notice.**
  - Acceptance: revoke succeeds under an exhausted operation budget (the
    exemption is a code-level URI list with a census); attempts carry
    distinct `id` and `issuedAt` and the same `noticeId`; the client's
    acknowledgement, from a sender with no ACL entry, stops the retries and
    records `revocation.notified`; a mediator handoff alone does not; nothing
    is sent after 24 hours; the schedule extends `PushReissuer`'s, with no
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
    governance tasks need the admin role through `act_scope()`; no token
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
    `#![cfg(feature = "hcp")]`, through `MockVta` and the transport harness
    over TSP with real gates; the happy path and each refusal (another VID's
    token, a revoked grant, a wrong purpose, REST, revoke under an exhausted
    budget) pass; the agent VID is a `did:webvh`; a transcript is recorded for
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
