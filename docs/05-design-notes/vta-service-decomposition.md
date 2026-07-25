# vta-service decomposition — extracting subsystems from the monolith

**Status:** in progress. Nine steps landed (#780–#791); the subsystem phase is
close to done. See [Where this stops](#where-this-stops) before proposing a
tenth.

`vta-service` was a single ~114k-line crate holding every VTA concern: key
management, the credential vault, WebVH hosting, policy evaluation, TEE
bootstrap, backup/restore, audit, TTL sweepers — plus the service's own HTTP
routes, Trust-Task dispatch, messaging bridge, and orchestration. Everything
recompiled when anything changed, no subsystem could be tested without standing
up the whole service, and the AWS KMS dependency stack sat in the default build
graph for every developer who would never run a TEE.

This note records what has been extracted, the technique, and — most
importantly — the rule for when to stop.

## Where it stands

| | `vta-service/src` |
|---|---|
| Before (#777) | 113,949 |
| After nine steps (#791) | **87,404** |
| Change | **−26,545 (−23%)** |

Extracted into eleven crates totalling 27,050 lines. The move is close to 1:1 —
26.5k left, 27.0k arrived — which is the signal that these were *moves*, not
rewrites.

## What LOC is and isn't measuring

Net workspace LOC went slightly **up** (~500 lines of new `Cargo.toml`,
`lib.rs`, and re-export boilerplate). Shrinking `vta-service` is a proxy, not
the goal. The goals it stands in for:

- **Compile-unit granularity.** Touching `vta-vault` no longer recompiles 87k
  lines of unrelated code.
- **Independent testability.** `vta-policy`'s 37 tests and `vta-tee`'s 32 run
  without constructing an `AppState` or standing up a service.
- **Narrow dependency surfaces.** The concrete win: `aws-sdk-kms`,
  `aws-sdk-dynamodb`, `aws-config`, `aes`, and `cbc` left the default build
  graph with `vta-tee`. A dev VTA no longer builds the AWS SDK.

If a proposed extraction moves lines without advancing one of those three, it is
not worth doing.

## The layering that emerged

Dependencies flow strictly downward, as everywhere else in the workspace.

```
Layer 0  vti-common      vta-sdk      vti-secrets        (pre-existing leaves)
             │              │              │
Layer 1  vta-keyspaces  vta-config   vta-audit
             │              │              │
Layer 2  vta-support   vta-keys   vta-vault   vta-webvh   vta-policy
             │              │              │
Layer 3  vta-tee       vta-backup   vta-sweepers
             │
Layer 4  vta-service                                      (the spine)
```

| Crate | Lines | Role |
|---|---|---|
| `vta-keyspaces` | 225 | Keyspace-name registry + the backup partition (`ALL` / `BACKED_UP` / `EXCLUDED_FROM_BACKUP`). Dependency-free leaf. |
| `vta-audit` | 217 | Structured audit logging, so any subsystem can emit events without depending on the service. |
| `vta-config` | 1,011 | `AppConfig` TOML shape and sub-configs, composed over `vti-common`'s shared types. |
| `vta-support` | 1,069 | Shared mid-layer services (trust-context storage, and the rest of the clean glue the subsystems need). |
| `vta-keys` | 2,885 | Master-seed storage, BIP-32 derivation, key wrapping, imported keys, `create_seed_store`. |
| `vta-policy` | 2,292 | Regorus (Rego) engine, default bundle, DTTE consent model, decision evaluators, policy storage. |
| `vta-webvh` | 2,373 | WebVH hosting infrastructure for the `did:webvh` lifecycle and its other consumers. |
| `vta-vault` | 8,668 | Holder credential vault — storage, query, receive/verify, present, status refresh. |
| `vta-backup` | 3,891 | Encrypted export/import (Argon2id + AES-256-GCM), compatibility check, two-phase descriptor flow, sealed bundle store. |
| `vta-tee` | 3,970 | TEE bootstrap: attestation providers, KMS attest/decrypt, storage-key derivation, anti-rollback anchor, Mode-B carve-out. |
| `vta-sweepers` | 449 | Background TTL sweepers for the core keyspaces. |

## Technique

Four patterns, in descending order of preference.

**1. Pure move behind a re-export facade.** The default. Code moves to the new
crate; `vta-service` keeps a `pub use` so `crate::policy::…`,
`vta_service::tee::…`, `crate::operations::backup::…` all still resolve. No call
site churns, so the diff is legible as a move and `vta-enclave` needs no change.
Do not take this as licence to keep the facade forever — but do not churn
hundreds of call sites in the same PR as the extraction, or the review becomes
impossible.

**2. Enabling move.** A small preparatory relocation that removes the single
coupling blocking a clean extraction. `derive_pre_rotation_keys` (a pure BIP-32
operation) moved from `operations::did_webvh` to `vta-keys` because it was
`vta-tee`'s only reach back into `vta-service`. The `Guards` /
`WebvhPathCounter` executor-precondition types moved to `vti_common::guards`
because they were the trust-task planner's only shared type with the consent
model. Both were a few dozen lines that unblocked thousands.

**3. Dependency inversion.** When the glue is genuinely service-specific, invert
through a trait rather than dragging `AppState` down a layer. The TEE KMS
re-encryption step of a backup import is injected via
`vta_backup::BootstrapReEncryptor`, whose sole implementation lives in
`vta-service`. Use this when a pure move would require the lower crate to know
about the higher one.

**4. Tests move with the code.** Each crate runs its own suite. This is what
makes "independent testability" real rather than nominal, and it is why the
extractions needed slim local fixtures (`vta-backup` has its own, so it needs no
dependency on `vta-service`).

Every step asserted **no behaviour change**: the full `vta-service` lib suite,
the new crate's suite, all feature combinations, the enclave build, and the
workspace build green before merge.

## Where this stops

This is the part to read before opening a tenth extraction PR.

**A subsystem is extractable. The service's own spine is not.** What remains in
`vta-service` is what makes it the service:

| Module | Lines | Why it stays |
|---|---|---|
| `operations/` | 38,686 | Orchestration. Depends on every subsystem; nothing depends on it. |
| `trust_tasks/` | 14,258 | The dispatch spine — the thing that routes to everything else. |
| `routes/` | 9,235 | The HTTP surface. Terminal by definition. |
| `messaging/` | 7,736 | The DIDComm/TSP bridge — the other terminal surface. |
| `setup/` | 3,790 | First-boot wizards. Consumes subsystems, is consumed by nothing. |
| `main.rs`, `server.rs`, `*_cli.rs` | ~13,000 | The binary, plus the offline-CLI entry points. |

Extracting `operations/` into a `vta-operations` crate would move 38k lines and
narrow **no** dependency surface: the new crate would still need every subsystem
below it, and `vta-service` would still need all of it. That is renaming, not
decoupling — it fails the test in
[What LOC is and isn't measuring](#what-loc-is-and-isnt-measuring).

So: **the subsystem phase is nearly complete, and completing it is the natural
end of the program.** Do not chase the LOC number further by carving up the
spine.

### The remaining legitimate candidates

Small, genuinely separable, and each worth doing only if someone can name the
build-time or testability win first:

- **`setup/` (3,790)** — a leaf-ward consumer: it uses subsystems and nothing
  uses it. The cleanest remaining extraction, and the least valuable, since the
  wizards are not on any hot compile path.
- **The offline CLI surface (~3k)** — `bootstrap_cli`, `services_cli`,
  `webvh_cli`, `vault_cli`, `acl_cli` form a distinct entry point (direct fjall
  access, no auth ceremony, not for TEE deployments). A `vta-offline-cli` crate
  would make that boundary explicit rather than conventional.
- **`test_support.rs` (1,427)** — a dev-only crate would keep test fixtures out
  of the release build graph.

### What is probably worth more than another extraction

- **In-file test modules are 22,622 of the remaining 87,404 lines (26%).** The
  non-test figure is 64,782. Any future LOC discussion should quote both numbers,
  because "87k" overstates the implementation by a quarter.
- **Measure compile time, not lines.** The program's actual justification is
  build latency and testability. Nobody has published a before/after on either.
  A recorded `cargo build --timings` delta across #780→#791 would tell us
  whether the 23% was worth nine PRs — and would settle the stopping question
  with evidence instead of judgement.

## Invariants to preserve

- **Dependencies flow strictly downward. No cycles.** The layering above is the
  contract; a new crate must slot into it, not straddle it.
- **Re-export facades keep call sites resolving.** Breaking `crate::x::y` paths
  and extracting in the same PR makes the change unreviewable.
- **Tests move with the code they cover.** A subsystem crate whose tests stayed
  behind has not really been extracted.
- **Extraction is behaviour-neutral.** If a step needs a behaviour change, land
  the behaviour change separately, before or after — never inside the move.
- **Feature gates travel with their subsystem.** `vta-tee` is behind `tee`;
  extracting it must not put the AWS stack back in the default graph.
