# Workspace engineering notes

The long form of the release, test and CI rules summarised in the
workspace `CLAUDE.md`: why each rule exists and the incidents behind it.
Release mechanics are in [`RELEASING.md`](../../RELEASING.md).

## Versioning & publishing (workspace-specific)

**Never edit a `version = ` field in a feature PR.** Versions are assigned by
the Release PR that release-plz maintains; merging that PR is what publishes.
Merging a feature PR publishes nothing. See [`RELEASING.md`](RELEASING.md).

That includes when the `semver report (informational — never blocks)` check
goes **red on your PR** (it runs only on a PR labelled `semver-report`; the
Release PR's `release bump is large enough` job enforces the same check). It is doing its job: it compares the crate's public
API against the version on crates.io, so a PR that adds a struct member or
renames a `pub const` *should* turn it red. The red is the report, not a
defect, and the fix is not a version bump in your branch — release-plz reads
the same signal and puts the bump in the Release PR.

Worth stating because the failure mode is not "someone ignored the rule". It
is reading a red check as a thing to fix, bumping the crate, watching the
check go green, and concluding it was the right move — three PRs did exactly
that before anyone opened the Release PR and found the identical bumps already
proposed there. A manual bump is not merely redundant: it collides with the
Release PR and fragments one coordinated release into several.

**The other red that job produces means one of three different things.** It
builds rustdoc twice per crate — the workspace copy (`current`) and the
crates.io copy (`baseline`) — and a failure of either reads the same in
`cargo-semver-checks` output. The baseline resolves **without a lockfile**, so
it takes the newest semver-compatible release of every dependency, including
ones `Cargo.lock` pins below; that is what makes it the only check here that
sees what a consumer's fresh `cargo add` sees, and also what makes it catch
somebody else's bad release. `scripts/semver-build-failure.py` does the
attribution and names the culprit package — read what it says before assuming
a published artifact of ours is broken. #1667 was exactly that mistake:
`vta-service` 0.39.0 was fine, `affinidi-messaging-mediator` 0.28.33 was not,
and it reaches us only through `vta-service`'s optional `transport-harness`
feature, so the default-feature reproduction the report printed never touched
it. A dependency break of this shape is fixed upstream or by a raised floor,
never by a change here.

**27 of 37 crates publish.** The ten that do not — `vta-enclave`,
`vta-mcp`, `vta-mobile-core`, `didcomm-test`, `vti-fuzz`, `vti-e2e-tests`,
`room-host`, `vti-rooms-wasm`, `vti-witness`, `vti-voting-service` — set `publish = false` in their
own manifest, each with a comment saying why. (The count is the workspace's
members plus `vti-fuzz`; the excluded `deploy/nitro/enclave-proxy` is a
deployment helper, not counted.)

The other 27 are `vta-sdk`, `vti-common`, `vti-secrets`, `vta-cli-common`,
`vtc-client`, `pnm-cli`, `cnm-cli`, `vtc-service` — plus `vta-service` and its
closure (`vta-audit`, `vta-backup`, `vta-config`, `vta-keys`, `vta-keyspaces`,
`vta-policy`, `vta-support`, `vta-sweepers`, `vta-tee`, `vta-vault`,
`vta-webvh`, `vta-persona`, `vti-webauthn`, `vta-external`, `vti-vetting-pcs`,
`vti-voting`, `vti-rooms`, `vti-rooms-dtg`).

**`vtc-service` is published as a binary**, so an operator installs the VTC
with `cargo install vtc-service`; nothing consumes its library, so it carries
no semver check (`release-plz.toml`, `scripts/semver-report.sh`). Its package
ships the admin console and member portal **pre-built** (`admin-ui/dist`,
`admin-ui/dist-members`, listed in its `include` though gitignored), never the
npm project: `publish.yml` runs `scripts/build-vtc-web-bundles.sh` before
release-plz, and `build.rs`, finding no `admin-ui/package.json`, bakes those
bundles instead of running npm. Cargo counts those gitignored-but-included
files as uncommitted, so it publishes with `--allow-dirty`
(`publish_allow_dirty`), the build step checking nothing else differs. A new `include_dir!` / `include_str!` outside
tests must stay inside that `include` list, or the published crate stops
building.

**`vta-service` is published for one reason and it is not its own API:**
`openvtc-core` dev-depends on it for `test_support::MockVta`, the in-process
VTA the OpenVTC end-to-end tests run against. That harness boots the real
service, so no client crate can stand in for it. #938 unpublished the crate on
the finding that no external consumer existed; the audit missed that
dev-dependency, and unpublishing did not merely freeze the crate — it **broke**
it. `vti-common` re-exports `vta_sdk::acl::{ActScope, ApproveScope,
ContextDirection}` as its own public API, so any graph combining `vti-common`
with another `vta-sdk` consumer must resolve **one** `vta-sdk`. A frozen
`vta-service` asking for `^0.21` beside a `vti-common` on `^0.23` gives two
nodes and `expected vti_common::acl::ApproveScope, found
vta_sdk::acl::ApproveScope`. Publishing keeps the requirements moving together.

That is also the rule in general: **a re-export makes the re-exported crate's
version part of your public API.** Before unpublishing anything, check for
dev-dependencies, not just normal ones.

Before adding a crate to the published set, check that everything it depends on
is published too — crates.io requires the whole closure, which is what puts the
thirteen `vta-*` subsystem crates on the registry behind `vta-service`.

release-plz handles the dependent ripple: a breaking bump moves a crate's
compatibility range, so every dependent's `version = "0.y"` requirement is
updated in the same PR. Use `major.minor` version pinning (not
`major.minor.patch`) for internal dependencies. Exception: crypto deps
(`ed25519-dalek`, `hpke`, `jsonwebtoken`, `aes-gcm`, `aws-lc-rs`) should
pin to a minimum patch to avoid silent regressions when a CVE lands.
The legacy `rsa` crate was replaced with `aws-lc-rs` in 0.5 for KMS CMS
unwrap (drops RUSTSEC-2023-0071 exposure); don't reintroduce `rsa`.

## Running the tests: green and wrong

All of these cost a day in September 2026 — #1341 broke main in 68 places and
the fix went four rounds (#1348, #1350, #1355, #1359), because each round only
revealed the next failure.

**A per-crate run compiles a fraction of the tests.** `cargo test -p vta-sdk`
runs **306**; the workspace run runs **742**, because feature unification from
sibling crates compiles code the crate alone does not. Three of `vta-sdk`'s
integration binaries have **no tests at all** under default features. So "the
crate's suite is green" can be true and mean almost nothing — and it is the
natural thing to run while working on one crate.

**`cargo test` stops at the first failing target.** One reported failure was
hiding sixty-seven. Fix the first and the second appears; fix that and sixty
more do. Use `--no-fail-fast` before concluding anything about scope, and
before believing a fix is complete.

**Reproduce what CI runs, not what seems equivalent.** CI's workspace job is
`cargo nextest run --workspace --exclude vtc-service --exclude vtc-client`
plus `cargo test … --doc` — default features. Chasing the same failure under `--all-features` finds real but
unrelated breakage (a stack overflow in `mock_vta`, nine failures elsewhere)
that CI never sees, and none of it is the thing that is red.

**A warning is an error, and only in CI.** `cargo clippy` prints warnings and
exits 0; the CI job is `-- -D warnings`, so the same output is a failure there.
`--all-targets` is part of it too — without it clippy sees only the lib and
bin targets, and dead code in `tests/` accumulates unseen. `vta-service` gets
two further clippy runs under reduced feature sets, which catch what the
default build cannot: a `#[cfg]` arm nothing else compiles.

So, before pushing a change that could touch another crate's tests, run what CI
runs:

```sh
cargo nextest run --workspace --exclude vtc-service --exclude vtc-client
cargo test --workspace --exclude vtc-service --exclude vtc-client --doc
cargo nextest run -p vtc-service -p vtc-client   # a separate CI job
cargo test -p vtc-service -p vtc-client --doc
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

**Tests run under nextest; doctests do not.** `cargo install cargo-nextest`
(or the prebuilt binary from <https://nexte.st>). `.config/nextest.toml` sets
`fail-fast = false` — the `--no-fail-fast` rule above, by default — and kills
a test after 5 minutes, so a hang ends with its name. nextest runs each test
in its own process, all binaries in one pool: `cargo test` runs one binary at
a time, and vtc-service's tests serialise on process-global locks, which kept
its two big binaries under one core. nextest never runs doctests, so the
`--doc` lines are not optional. `cargo test` still works and still means the
same thing; it is only slower.

**CI caches compiled third-party crates, never the workspace's own.**
`.github/actions/rust-cache` (Swatinem/rust-cache, saved from `main` only, keyed
per job) restores dependencies and deletes every workspace member's artifacts
before saving — so the stale-artifact failure that removed the old `target/`
cache (#1133) cannot recur. Keep every local path crate a workspace member, or it
would be cached as a "dependency". The same action links with mold. There is no
`Check` job (Clippy `--all-targets` covers it), tier-2 jobs wait for Clippy
only, and `scripts/ci-affects.sh` skips every compile job for a prose-only PR.

**Dependencies build at `opt-level = 2`** (`[profile.dev.package."*"]`;
workspace crates stay at 0, so an edit-test loop recompiles nothing extra).
At 0 the suites spent their CPU in other people's code — regorus re-parsing
the default policy bundle for every vtc-service test, Argon2id at 64 MiB in
vta-backup (89s of one CI run). The first build after a `Cargo.lock` change
pays for the optimisation once.

**On macOS the test fixtures used to queue on the disk.** Measured on an
18-core Mac (load average 3–7 from other builds; treat as indicative):
`cargo test -p vtc-service --lib` 1085s / 1111s at opt-level 0, 984s at 2,
893s under nextest; the `it` binary 1434s / 2689s. Linux CI runs the same lib
binary in ~141s. A sampled test spent 2.9s wall for 0.5s of CPU, nearly all
of it in `fcntl(F_FULLFSYNC)` — `lsm_tree`'s `fsync_directory` while
`build_test_vtc` created its ~45 fjall keyspaces. `File::sync_all` is
`F_FULLFSYNC` on macOS, a whole-device cache flush, so parallel test
processes queued on the disk rather than the CPU. fjall has no setting that
skips those fsyncs (keyspace creation is durable unconditionally), so the
fixtures (`TestVtc`, and `vta_service::test_support`'s `open_test_store`,
`build_signing_test_app_state*` and `build_test_app_with`) now copy a
pre-built template database instead of creating keyspaces —
`vti_common::store::test_fixture`, published once under
`$TMPDIR/vti-store-templates/`. `ceremony::`, `backup::tests` and `acl::`
(157 tests) went 16.3s → 3.6s on the real disk; running with `TMPDIR` on a
RAM disk is no longer needed for tests built on those fixtures. Unit tests
that call `Store::open` themselves still create their keyspaces the slow way;
a new multi-keyspace fixture should use `open_with_keyspaces`.

## A merge is not evidence that anything passed

The only **required** status check on `main` is `DCO`. Every job above — the
build, both test jobs, clippy, fmt, MSRV, `cargo-deny` — is advisory, so a
pull request merges on a red suite exactly as readily as on a green one, and
no prompt appears.

This is not hypothetical and it is why the section above exists. On 9 September
2026 `main` was red for five and a half hours across six consecutive merges —
#1341, then #1344, #1346, #1348, #1350 and #1355 — each landing on an already
failing main, until #1359 returned it to green. The account of it that first
reached this file said "#1341 merged green", which is the natural reading and
is false: nothing was checking.

Two things follow, and both are habits rather than rules:

- **Do not read a merge as evidence its suite passed.** Read the run. And read
  the run's own jobs (`gh api repos/.../actions/runs/<id>/jobs`) rather than the
  aggregate rollup, which reports staleness as success across a re-run.
- **Do not assume a red main is your regression.** Check when it went red
  first. It may have been red since before you branched, and the failure you
  are looking at may be somebody else's — or your own, four merges ago.

Whether the CI workflow should be a required check is a repository-settings
decision that has not been taken. Until it is, the discipline above is what
stands in for one.
