# VTC Architecture Simplification & Hardening Plan

Source: full architecture review of vtc-service (2026-06-10, six-subsystem
fan-out review covering auth/ACL/install, credentials/status-lists/recognition,
membership/ceremony/policy, registry/messaging/audit, server/config/setup, and
the HTTP edge). This document is self-contained — it can be executed over time
without the original review conversation. Task checklist:
`tasks/vtc-architecture-todo.md`. Companion to the VTA plan
(`tasks/vta-architecture-plan.md`) — VTC shares the team's house patterns and
several of the same bug classes, but is a distinct ~44k-LOC crate.

**Goal:** close the security gaps found (the VTC handles a community's
irreplaceable social state — members, ACL, endorsements, status lists, audit —
none of it TEE-protected), make the service harder to misconfigure, and
converge VTC's divergent surfaces onto the four house patterns it already
contains but applies inconsistently:

1. `vti-common::auth` extractors/handlers — for *all* token-mint paths
2. Thin route adapters + `operations`/`ceremony` orchestration — for *all*
   business logic (the VTC keeps decide→effect→audit spines in `routes/`)
3. The `VerifiedFacts` / typestate `Verified*` discipline — for *all* wire
   forms whose claims drive a decision
4. A single config registry (`config_store`) + single `AppState` — for *all*
   config mutation and derived runtime state

## How to use this plan

- Each task is one PR-sized vertical slice: root-cause fix + regression test +
  doc touch, verified before merge. No horizontal "change all signatures" PRs.
- Conventions per workspace CLAUDE.md: `cargo fmt`, DCO-signed commits (`-s`),
  full CI (tests, clippy, cargo deny) before opening a PR, branch off main only
  after the prior PR merges.
- Sizes: **S** ≤ ½ day, **M** 1–2 days, **L** 3–5 days, **XL** needs its own design note.
- Order within a phase is flexible unless a dependency is listed. Phase 0 fixes
  can land any time; don't start a phase's *refactors* until its checkpoint passes.
- Tick items off in the todo file as they merge; record the PR number there.
- **VTC never targets TEE** (permanent non-goal). So unlike the VTA, there is no
  enclave-rollback / KMS-bootstrap / attestation work here — but encryption-at-rest
  for the keyspaces that hold private keys still matters (P0.7).

## Dependency graph (phase level)

```
Phase 0 (security/correctness fixes) ──────────────┐  independent, parallelizable
                                                    ▼
Phase 1 (kill the divergence engines) ──► Checkpoint 1
        P1.1 config-mutation unification ─► P2.* (single config surface)
        P1.4 facts/sig helper extraction ─► P2.4
                                                    ▼
Phase 2 (collapse adapter shells + move logic out of routes) ──► Checkpoint 2
                                                    ▼
Phase 3 (strategic convergence + hygiene)
```

---

## Phase 0 — Security & correctness fixes (do regardless of any refactor)

These are bugs/gaps, not refactors. Mostly independent; land in any order.
Highest severity first.

### P0.1 — Status-list row needs concurrency control: revocations and slot allocations are silently lost (M)
**Problem:** every status-list mutation is an unsynchronized read-modify-write —
`get_state` → `allocate`/`flip` in memory → `store_state` whole-row overwrite
(`status_list/storage.rs:99-119`). The only mutex in that subsystem is
`LAST_ADMIN_LOCK` (`ceremony/execute.rs:64`), which does **not** cover status
lists. Call sites that race on the same purpose row interleave as
last-writer-wins over the entire 16 KiB bitstring + `assigned` mask
(`ceremony/execute.rs:234-279,466-477`, `routes/endorsements.rs:135-146,349-361`,
`credentials/invitation.rs:43-70`, `routes/members/renew.rs:100-124`,
`routes/members/rotate.rs:581`, `routes/members/personhood.rs:286-298`). Two
concrete failures, both reachable (REST + DIDComm handlers share `AppState`):
(a) a `revoke` flip racing a concurrent `allocate`+store silently clears the
revocation bit → a credential the operator believes revoked resolves valid;
(b) two concurrent `allocate`s read the same row, the second store drops the
first's `assigned[slot]=true` → future re-allocation aliases two members on the
bitstring (the exact correlation harm #149's `assigned` mask exists to prevent).
**Change:** a process-wide `static STATUS_LIST_LOCK` (mirroring `LAST_ADMIN_LOCK`)
held across get→mutate→store at every call site, or push the RMW into one fjall
transaction in `storage.rs`. Prefer a `status_list::with_locked(purpose, |row| …)`
helper so callers can't forget it. Wrap the revoke flip + `mark_revoked`
(`endorsements.rs:349-366`, `ceremony/execute.rs:466-477` + caller) under the
same lock so they're atomic together.
**Accept:** N concurrent `allocate` calls yield N distinct slots and
`count_assigned() == N`; a `flip(revoke)` interleaved with a concurrent
`allocate` keeps the revocation bit. Regression shape: `tokio::join!` of two
issuance futures over a shared `AppState`.

### P0.2 — Cross-community `recognise` is a bearer flow: no holder proof, no VMC↔VEC subject binding, no replay nonce (L)
**Problem (three bound-together gaps in the most security-sensitive
cross-org path):**
(a) `POST /v1/auth/recognise` accepts a raw `(VEC, VMC)` JSON pair and mints a
session JWT to the VEC's `credentialSubject.id` with **no proof the caller
controls that subject's key** — no challenge, no nonce, no holder signature, no
`aud` binding (`routes/recognise.rs:49-53,77-142`, verifier
`recognition/verify.rs:162-252`). Anyone who observes/exfiltrates a member's
VEC+VMC (plaintext signed JSON, no holder binding) replays them indefinitely to
impersonate that subject in every recognising community. Contrast the join
`present` path, which requires a holder proof bound to a single-use
`present_challenge` nonce. The `recognise.rs:218` comment calls this "a
single-factor proof of the subject DID" — but no proof occurs.
(b) `verify_foreign_vec` checks `vec.issuer == vmc.issuer` but never checks
`vmc.credentialSubject.id == vec.credentialSubject.id` (`verify.rs:162-252`,
`extract_role_claim` reads only the VEC). The VMC's only job is the "is a live,
non-revoked member" gate; without subject-binding, member A's role VEC + any
other current member B's unrevoked VMC (same issuer) passes the gate even after
the foreign community revoked A.
(c) The denied-path audit envelope takes its actor DID from the *unverified*
VEC subject field on an unauthenticated endpoint (`recognise.rs:112,363-392`,
`credential_subject_id_for_audit` at `:401-412`) — attacker-controlled actor
strings injected into the audit trail.
**Change:** require a holder presentation — issue a single-use challenge (reuse
`present_challenge`), accept the VEC/VMC inside a holder-signed VP/kb-jwt bound
to nonce + this VTC's DID, verify via the existing `verify_vp_token`/
`verify_di_vp`, and require the verified holder DID == VEC subject. Add the
`vmc.subject == vec.subject` check. Tag denied-path audit actors as untrusted
(prefix `unverified:` or actor `None` + `claimed_subject` data field). Update
spec §8.4.
**Accept:** replaying a captured VEC+VMC without a fresh holder proof → 401/403;
a VEC for `did:key:zA` + VMC for `did:key:zB` (same issuer) → rejected; a valid
holder-bound presentation with matching subjects → session minted; denied audit
envelope carries no unverified DID as a verified actor.

### P0.3 — DIDComm handlers trust the plaintext `from`, not the authenticated sender (M)
**Problem:** `HandlerContext.sender_did` is populated from the plaintext `from`
header (upstream listener `message.from.clone()`), not the authcrypt-authenticated
`skid`/`encrypted_from_kid`. The VTC router installs **no `MessagePolicy`**
(`messaging.rs:100`), so anoncrypt is accepted and `authenticated` is never
required, and no handler inspects the `UnpackMetadata` argument
(`messaging.rs:225-391`). The join-submit, join-accept, self-remove, and status
handlers all treat `ctx.sender_did` as the proven applicant/member DID
(`remove_inner(&caller_did, &caller_did, …)` is the worst — self-remove *as the
victim*). This violates the house invariant that unpacking yields a
cryptographically-authenticated sender DID.
**Change:** require `meta.authenticated && !meta.anonymous_sender` and that the
DID of `meta.encrypted_from_kid` equals `message.from` in each handler — or add
`.layer(MessagePolicy::new().require_authenticated(true).allow_anonymous_sender(false))`
to the router AND derive `sender_did` from `encrypted_from_kid`. Fix self-remove
first.
**Accept:** a message whose plaintext `from` ≠ the authcrypt key DID is rejected;
an anoncrypt message to `member_self_remove_handler` is rejected; regression test
asserts the handler reads `encrypted_from_kid`, not `from`.

### P0.4 — Redirect-following SSRF bypass + no timeout/size-cap on the unauthenticated foreign-fetch path (M)
**Problem:** `guard_status_list_url` (`recognition/verify.rs:557-655`) is a solid
allowlist (https-only, rejects IP-literals/RFC1918/metadata/userinfo) but runs
**once on the original URL**; the fetch uses `reqwest::Client::new()` which
follows up to 10 redirects by default, so a foreign credential pointing at
`https://attacker/list` that 302s to `http://127.0.0.1/...` or
`169.254.169.254` reaches the internal target (`recognise.rs:108`,
`present.rs:273,275`). The same client has **no `.timeout()`** and reads the body
with `resp.json()` — no size cap (`verify.rs:643-646`, `upstream.rs:273-277`) —
on the unauthenticated recognise route; a hostile host stalls the lone REST
thread or OOMs the daemon with a multi-GB body. `UpstreamRegistryClient::new`
sets a timeout; recognise/present don't (inconsistent hardening).
**Change:** one shared client built with `.timeout(...)` +
`.redirect(Policy::none())` (or a custom policy re-running `guard_status_list_url`
on every hop), injected into `HttpStatusListFetcher`; read the body against a
1–2 MB cap before `serde_json`.
**Accept:** an in-test server that 302s to `127.0.0.1` makes `check_status_bit`
return `StatusListFailed` (no internal fetch); a hung server trips the timeout;
an oversized body fails rather than OOMs; no `reqwest::Client::new()` remains on
these paths.

### P0.5 — Unauthenticated crypto endpoints left on the ungoverned 1 MB chain (M)
**Problem:** `recognise` was deliberately moved onto `build_unauth_routes`
(64 KB cap + 5 rps governor) for its attacker-controlled crypto, but three
sibling endpoints driving identical work were left on the main `api` chain
(1 MB cap, no limiter): `POST /v1/join-requests` (`submit.rs:100`, Ed25519
holder-binding verify + Rego eval), `POST /v1/join-requests/{id}/accept`
(`accept.rs:79`, VC counter-sign verify), `POST /v1/join-requests/{id}/status`
(`status.rs:46`, holder-binding verify) — all confirmed no auth extractor
(`routes/mod.rs:669-715`). CPU-amplification/DoS at 16× the body size with no
per-IP throttle.
**Change:** move all three POST registrations into `build_unauth_routes`; split
the shared `/v1/join-requests` mount so the admin `GET` list stays on `api` while
the unauth `POST` moves to the governed branch.
**Accept:** a router-enumeration test asserts every handler with no auth
extractor is on the governed branch; >10 rapid `POST /v1/join-requests` from one
IP returns 429.

### P0.6 — Join-request retention sweeper is defined but never spawned: VP/PII retained forever (S)
**Problem:** `RetentionSweeper::spawn` is the documented "sole control on
inadvertent PII retention" (`join/retention.rs:55-89`) but a workspace search
shows it is only defined + re-exported, never spawned in `server.rs` (which
spawns the registry health probe and `MembershipSyncer`). `Rejected`/`Withdrawn`
join requests — each holding the full submitted VP (up to 256 KiB, PII per the
docs) — are never purged, and `join_requests:` grows unbounded. Same class:
`credx-pending:` offers and `present-challenge:` records
(`credentials/exchange.rs:1144-1196`, `present_challenge.rs:53-95`) have TTLs
enforced only on the read path and are never swept (the join sweeper lists only
the `join_requests:` prefix); and registry `Failed` sync jobs are never reaped
(`syncer.rs:299,338`; `model.rs:143-145` comment claims a sweeper that doesn't
exist).
**Change:** spawn `RetentionSweeper` in `server.rs` wired from `JoinRequestsConfig`;
extend it (or add siblings) to also sweep expired `credx-pending:`/
`present-challenge:` rows and `Failed` sync jobs past a retention window. Fix the
`model.rs` comment.
**Accept:** a `Rejected` row dated 31 days ago is gone after the initial sweep;
expired `credx-pending`/`present-challenge` rows are GC'd; an old `Failed` sync
job is reaped; a not-yet-expired row of each kind survives.

### P0.7 — Encryption-at-rest for keyspaces holding private keys / audit keys (M)
**Problem:** `vti_common::store::KeyspaceHandle::with_encryption` exists and the
VTA uses it; `rg with_encryption vtc-service/src` → zero hits
(`server.rs:199-224` opens every keyspace bare). At-rest in plain fjall JSON:
the install-token ephemeral Ed25519 **private** key
(`install/state_machine.rs:77-83`, valid until claim/expiry — stealing it plus
the URL token defeats half the install ceremony), the HMAC `audit_key` keyspace
(forgeable actor hashes), and WebAuthn `passkey` state. The signing bundle
correctly lives in the seed-store backend, not a keyspace.
**Change:** derive a storage key (HKDF from the bundle Ed25519 seed, info
`vtc-storage-key/v1`) in `init_auth`, apply `with_encryption` to at least
`install`, `audit_key`, and `passkey`; add a try-decrypt-else-plain read path for
existing deployments.
**Accept:** on-disk bytes for an issued install token don't contain the base64
of the ephemeral key; a boot over a pre-encryption store still reads rows.

### P0.8 — Secret-store factory silently falls back when the backend isn't compiled; typo'd keys ignored (S)
**Problem:** each backend arm in `create_secret_store`
(`keys/seed_store/mod.rs:42-95`) is `#[cfg(feature)]`-gated with no `else`. A
config that sets `secrets.aws_secret_name` on a binary built without
`aws-secrets` compiles that arm away and silently selects the keyring (or
plaintext) → empty store → boot proceeds with "no key material found — auth
endpoints will not work" as a mere `warn!`. No config struct carries
`deny_unknown_fields` (`config.rs:420-440`), so `aws_secretname` (typo) is
silently dropped → identical fallback. (The wizard's plaintext path is a proper
loud opt-in; the runtime factory is the weak link.)
**Change:** add `#[cfg(not(feature))]` arms returning
`AppError::Config("secrets.aws_secret_name set but binary built without
'aws-secrets'")` for every set-but-uncompiled backend field; add
`#[serde(deny_unknown_fields)]` to `SecretsConfig` (full `AppConfig` needs an
alias audit first — `community_name`/`community_description` aliases exist).
**Accept:** per-backend test: field set + feature off → `Err`; unknown key under
`[secrets]` → parse error naming the key.

### P0.9 — Configured-but-broken identity boots into warn-and-serve-dead instead of failing hard (S)
**Problem:** `init_auth` (`server.rs:1048-1079`) returns all-`None` (daemon
serves, auth dead) in four cases: `vtc_did` unset (legitimate pre-setup), secret
store empty, secret store **errored**, and bundle-DID **mismatch**. The last
three happen on a daemon that *was* configured (keyring lost, AWS perms broken,
wrong service name) — the only signal is a log line, while monitoring sees a
healthy listener and every auth/issue/install call 503s.
**Change:** distinguish `vtc_did == None` (degraded boot, current behavior) from
`vtc_did == Some(_)` + secret missing/erroring/mismatched (return `Err` from
`run()`, exit non-zero with the operator hint).
**Accept:** config with `vtc_did` set + empty store → `server::run` returns
`Err`; config with no `vtc_did` → boots.

### P0.10 — Single-threaded REST runtime + synchronous Argon2id + no request timeout (M)
**Problem:** the REST surface runs on `new_current_thread`
(`server.rs:921-924`). Store ops are `spawn_blocking` (fine) but CPU-bound work
runs inline: Argon2id verify on the unauth `/v1/install/claim/start`
(`claim_secret.rs:63-74`, m=19456 KiB t=2, ~50–200 ms), Rego eval, VC signing —
each blocks every concurrent request. A handful of distinct source IPs hitting
claim-start saturate the lone thread (the 5 rps governor is per-IP). No
`TimeoutLayer` anywhere, so one wedged handler (a registry call without its own
timeout) holds its connection forever.
**Change:** wrap `claim_secret::verify`/`hash` (and other CPU-bound calls) in
`spawn_blocking`; add `tower_http::timeout::TimeoutLayer` (~30 s) to the router
stack; consider `new_multi_thread().worker_threads(2..4)` for the REST runtime.
**Accept:** a slow handler doesn't delay a concurrent `/health` past the timeout;
claim-start verify no longer runs on the async thread.

### P0.11 — `relationships_by_did` index scan leaks other DIDs' rows (colon-prefix collision) (S)
**Problem:** index key is `relationships_by_did:<did>:<uuid>`, `list_for_did`
scans prefix `<did>:` (`relationships/storage.rs:27-33,144-186`). `did:webvh`
DIDs legitimately contain colons: for `did:webvh:scid:host` vs
`did:webvh:scid:host:acme`, the scan prefix `…host:` matches the second DID's
keys, and `list_for_did` never post-filters on
`rel.issuer_did == did || rel.subject_did == did` → returns another DID's
relationship rows (cross-member information exposure).
**Change:** length-prefix/escape the DID in the index key, or (minimal)
post-filter hydrated rows by issuer/subject equality.
**Accept:** store edges for `did:webvh:s:h` and `did:webvh:s:h:x`;
`list_for_did("did:webvh:s:h")` returns only the first DID's edges.

### P0.12 — `Presentation.verified = true` stamped over cryptographically-unverified VCs on the submit path (M)
**Problem:** on the REST/DIDComm join-submit path only the *outer* holder-binding
signature is checked; the VP's embedded VCs are projected straight from
attacker-controlled JSON into ceremony `Credential`s and the wrapping
`Presentation` is stamped `verified: true` (`submit.rs:378-442`, esp. `:396`).
`facts.rs` documents `Presentation.verified` as "VP proof + holder-binding
checked out" and `VerifiedFacts::assemble` treats it as the authenticity gate.
The shipped `join.rego` requires `issuer_trusted` (hardcoded `false` here) so the
default can't auto-admit — but any operator policy branching on
`evidence.presentation.credentials[].claims` (e.g. "allow if email ends
@acme.com") auto-admits on a **fully forged VC**. The verifying `present.rs` path
makes the inconsistency invisible (identical-looking facts, opposite guarantees).
**Change:** either cryptographically verify each embedded VC on the submit path
before projecting (reuse `present.rs`/`recognition` verifier), or set
`Presentation.verified = false` (or a distinct `holder_binding_only` flag) on the
raw-VP submit path so a claims-reading policy is fail-safe. Never present
unverified VC claims under `verified: true`.
**Accept:** submitting a VP whose embedded VC carries an invalid proof yields
facts that do **not** carry `presentation.verified == true` (or the request is
rejected).

### P0.13 — Join-submit holder signature has no freshness/nonce/audience binding (replayable) (S)
**Problem:** the signed payload is
`domain_tag || canonical_json({applicantDid, vp, registryConsent, extensions})`
(`submit.rs:444-512`) — no nonce, no timestamp, no VTC/community DID. A captured
submit body is replayable indefinitely (each replay persisting a new ≤256 KiB
row — compounds P0.6) and replayable against a *different* community (no audience
binding). The `present.rs` path binds a single-use nonce + audience; the legacy
submit path doesn't. Also: no dedup against an existing open request from the
same `applicant_did`, and `Pending`/`Deferred` are never retention-eligible
(`join/mod.rs:54-56` `is_terminal_retainable`).
**Change:** bind a server-issued single-use challenge (or at minimum the VTC DID
as audience + a `created` timestamp with a short window) into the signing
payload; dedup open requests per `applicant_did` (return the existing one or 409)
and/or cap open requests per applicant.
**Accept:** replaying a captured submit body, or submitting against a different
community DID, is rejected; a second submit for the same applicant yields one row
or a 409.

### P0.14 — Promote-to-admin bypasses the role-change policy entirely (M)
**Problem:** `update.rs` refuses `role=admin` on PATCH specifically so the
role-change policy's step-up branch is reached "there" (the promote endpoint),
but `promote_finish` (`routes/members/promote.rs:131-218`) runs **no policy at
all** — passkey UV ceremony, then a direct `target_acl.role = VtcRole::Admin`
write. The operator-authored `vtc.role_change` policy (the documented governance
surface for the single most privileged grant) is never consulted on the actual
admin-promotion path; an operator who tightens `role_change.rego` (quorum/tenure)
is silently ignored.
**Change:** route promote-to-admin through the role-change ceremony (`decide`
over `PolicyPurpose::RoleChange` with `step_up: true` after UV passes, then
`EffectPlan::Remint`) so policy + host invariants apply.
**Accept:** a `role_change.rego` returning `deny` for an admin promotion causes
`promote_finish` to 403 even after a valid UV.

### P0.15 — `admit` lacks the serializing lock the other effect arms use: duplicate-credential TOCTOU (S)
**Problem:** `depart` and `remint` run check-then-write under `LAST_ADMIN_LOCK`,
but `admit` (`ceremony/execute.rs:177-215`) does a bare `get_acl_entry(...).is_some()`
guard then writes ACL/member/VMC/slot with no lock. Two concurrent admits for the
same subject DID (two `Pending` approved in parallel, or a submit auto-admit
racing an approve) both observe "no ACL row," both proceed → two VMCs minted, two
status-list slots burned, audit double-counts.
**Change:** take a per-subject (or the existing global) lock across the existence
check + writes in `admit`, matching `depart`/`remint`.
**Accept:** two simultaneous admits for one DID → exactly one VMC and one slot;
the loser gets `Conflict`.

### P0.16 — Non-admin `VtcRole` ACL rows make the unauth `/auth/challenge` 500 and leak serde internals (M)
**Problem:** `VtcAuthBackend::check_acl` (`auth/backend.rs:108-112`) resolves
roles through `vti_common::acl::check_acl_full`, which deserializes the `acl:<did>`
row into a `vti_common::acl::AclEntry` whose `role` is the VTA taxonomy. VTC
writes `VtcAclEntry` rows whose role serializes as `moderator`/`issuer`/`member`/
`custom:<name>` and `POST /v1/acl` permits creating them. When such a DID hits
the unauthenticated `POST /v1/auth/challenge`, the foreign deserializer fails with
`unknown variant 'moderator'` → `AppError::Internal` → **HTTP 500 whose body
leaks the serde text** to an unauthenticated caller, and every non-admin VtcRole
silently can't authenticate. Fails closed (not an escalation) but is a reachable
correctness + info-leak bug and the unfinished Phase-2 `VtcRole`↔`Role` migration
(`acl/storage.rs:9-18`).
**Change:** make `check_acl` read the VTC row via `crate::acl::get_acl_entry`
(decodes `VtcAclEntry`), map `VtcRole → vti_common::acl::Role`, apply the VTC
row's own expiry check, and return a clean `Forbidden`/role instead of letting
the foreign deserializer 500.
**Accept:** creating a `moderator` ACL entry then calling `/auth/challenge` for
that DID → clean 403 (no serde text in body); an admin row still authenticates.

### P0.17 — Secret-bearing files written world-readable (S)
**Problem:** every `config.toml` contains `auth.jwt_signing_key` (the Ed25519 JWT
signing seed) and, under the config-secret backend, the hex-encoded `VtcKeyBundle`
with both private keys — written via `std::fs::write` → default umask (0644)
(`setup/wizard.rs:1317-1337,189-194`, `routes/config.rs:76`).
`PlaintextSecretStore::set` likewise writes key material 0644
(`keys/seed_store/plaintext.rs:59-68`). The workspace pattern elsewhere is 0600 +
Windows ACL hardening (PNM bootstrap-secrets).
**Change:** `OpenOptions::mode(0o600)` (or chmod after write) on `config.toml` in
the wizard and the `/v1/config` save path, and on `secret.plaintext`; reuse the
PNM 0600 helper.
**Accept:** unix test — `write_config_toml` and `PlaintextSecretStore::set`
produce mode-0600 files.

### P0.18 — Rego evaluation has no timeout/instruction budget: DoS on the unauth join path (M)
**Problem:** `policy/engine.rs:110-124` clones the engine, sets input, and calls
`eval_query` with no loop/instruction/time bound and no input-size cap. The join
decision policy is evaluated on the **unauthenticated** submit route against
attacker-influenced facts (the VP + claim graph flow into `input`). A pathological
operator-uploaded policy or adversarial input shape burns CPU per request; the
governor caps to 5 rps/IP but each request stays expensive.
**Change:** configure a regorus evaluation bound (instruction/loop limit and/or
wrap each `evaluate` in `tokio::time::timeout` on a blocking task); cap the
serialized `input` size before evaluation; fail closed (default-deny) on bound
exceeded.
**Accept:** a deliberately expensive policy/input aborts with a deny rather than
hanging the handler; an input-size-cap unit test.

### P0.19 — `vtc status` trust-ping broken for every production deployment (S)
**Problem:** `status.rs:269-274` (`send_trust_ping`) rejects key material whose
length ≠ 64 bytes, but the wizard has stored the JSON `VtcKeyBundle` shape since
the VTA-driven-keys rework, so on any real deployment the status command's
mediator ping fails with a baffling byte-count error (only legacy/test fixtures
pass). `decode_secret_store_value` (`server.rs:1333-1362`) already handles both
shapes.
**Change:** replace the manual split with `decode_secret_store_value`; move that
helper out of `server.rs` into `setup::bundle` or `keys`.
**Accept:** `send_trust_ping`'s key-extraction accepts a JSON bundle fixture; the
64-byte fixture still works.

### P0.20 — Privilege/scoping gaps in ACL + session management (S)
**Problem (cluster):** (a) `DELETE /v1/acl/{did}` is gated on `ManageAuth`
(Admin **or** Initiator) while the strictly-less-destructive `PATCH` is gated on
`AdminAuth`; neither inspects the *target* entry's existing role, so a
context-admin of `ctx-a` can delete/downgrade a peer admin whose
`allowed_contexts` merely overlaps `ctx-a` (`routes/acl.rs:159-229`). (b)
`revoke_sessions_by_did` and `session_list` (`routes/auth.rs:841-906`) have no
context scoping — any context-admin can revoke any member's (or a super-admin's)
sessions community-wide, and `session_list` returns the full member roster +
session metadata. (c) `update_acl` rewrites the ACL row but doesn't revoke the
subject's live sessions, and the `AuthClaims` extractor reads role/contexts from
the still-valid JWT (only refresh re-checks ACL), so a demoted admin keeps admin
authority for the full access-token TTL.
**Change:** gate `delete_acl` on `AdminAuth`; when the target is `VtcRole::Admin`
require super-admin (or assert the caller administers *every* context the target
holds). Scope `revoke_sessions_by_did`/`session_list` to the caller's visible
contexts. On any downgrade in `update_acl`, revoke the subject's sessions.
**Accept:** context-admin of `ctx-a` can't delete an admin scoped to
`[ctx-a, ctx-b]`; `session_list` for a context-admin omits out-of-context
sessions; a demoted admin's old bearer is rejected on the next request.

### P0.21 — Install `claim/start` takes the 5-minute ceremony lock before verifying the claim secret (S)
**Problem:** `claim_start` (`routes/install.rs:122-142`) calls `start_claim(&jti)`
— which sets `claimed_at` and locks out concurrent claims for 300s
(`install/state_machine.rs:220-268`) — **before** verifying the OOB claim secret.
The claim secret exists so "a leaked install URL is not enough," but an attacker
holding only the URL can POST `claim/start` with a wrong code every 5 minutes;
each call refreshes the lock and is rejected *after* locking → the legitimate
operator is held off indefinitely (the 5 rps governor doesn't help).
**Change:** verify the claim secret (add `peek_secret_hash`/reuse `get_token` +
`claim_secret::verify`) before acquiring the ceremony lock; never let a
failed-secret attempt set `claimed_at`.
**Accept:** `claim/start` with the wrong code followed immediately by the correct
code succeeds (no lockout).

**Checkpoint 0:** all P0 merged or explicitly deferred with an issue; full CI
green; `docs/03-vtc/cross-community.md` (recognise holder-binding) and
`docs/05-design-notes/vtc-mvp.md` §14 updated to reflect P0.2/P0.3/P0.7 status.

---

## Phase 1 — Kill the divergence engines (small PRs, high correctness leverage)

### P1.1 — One config-mutation surface; boot-stable derived state made explicit (L) — DO FIRST
**Problem:** config mutation is split across three uncoordinated surfaces with
three auth levels and two audit regimes: legacy `PATCH /v1/config`
(`routes/config.rs`, super-admin, writes TOML), the `config_store` registry
overlay (`config_store.rs` + `routes/admin/config.rs`, admin, writes fjall), and
`CommunityProfile` (`community/profile.rs`, admin, writes the `community`
keyspace). Symptoms: (a) `PATCH /v1/config` can rewrite `vtc_did`/`vta_did` →
next-boot auth-dead or recovery-authority re-pointed (`config.rs:42-80`); (b) it
serializes the env-overlaid struct back to TOML (baking ephemeral `VTC_*`
overrides in permanently), skips `validate_routing_and_cors`, and writes
non-atomically (`config.rs:69-76`); (c) community name/description live in **both**
`config.toml` and the `CommunityProfile` row with nothing synchronizing them; (d)
five derived values are computed once at boot and silently diverge from runtime
`PATCH` (`Webauthn` RP handle, `AppState.public_url` snapshot, status-list
`list_credential_id` URLs, CORS/routing layers, the DIDComm thread's whole-config
clone — `server.rs:334-349,110-115,260-276,610-611`).
**Change:** make `config_store` the single canonical overlay; migrate
`public_url` into it as a `requires_restart` key; declare `CommunityProfile` the
sole owner of name/description (`GET /v1/config` reads from it, keep serde
aliases); drop `vtc_did`/`vta_did` from the legacy update body (return 409,
"identity is set at `vtc setup`"); route all writes through one `save()` that
resets env-sourced fields, validates, and writes tempfile-then-rename; have
`update_config` respond with a `requires_restart` indicator for boot-stable keys.
Delete/410 the legacy PATCH once the admin UI moves.
**Accept:** one write path per field; PATCH with `vtc_did` → 409 and config.toml
unchanged; `VTC_*` env overrides don't leak into TOML on a PATCH; name set via
profile PUT is what `GET /v1/config` returns; PATCH of a boot-stable key returns a
restart-required indication.

### P1.2 — Config-mutation audit + real actor DID (M)
**Problem:** `PATCH /v1/admin/config` (the primary runtime-config surface) emits
**no** audit envelope, though `reload`/`restart`/`import` on the same file do
(`routes/admin/config.rs:130-132`); legacy `PATCH /v1/config` and
`PUT /v1/community/profile` are also unaudited while the *import* path for the
identical profile fields is audited — auditability depends on which of three
equivalent doors the admin used. Where audit does fire, the actor is the literal
`"did:key:vtc-admin"` sentinel (`:220,278,586`) though the real DID is in the
`AdminAuth` extractor every handler already takes.
**Change:** emit `ConfigChanged` from `patch_config` (the `ConfigChange::redact_if`
machinery exists), `CommunityProfileUpdated` from `put_profile`; replace every
sentinel with `_admin.0.did`.
**Accept:** PATCH admin config and PUT profile each produce an audit row whose
actor hash matches the calling admin DID; grep for `did:key:vtc-admin` returns
only the migration note.

### P1.3 — Registry/RTBF audit envelopes must not be fire-and-forget (S)
**Problem:** `emit_override` (the `RegistryRecordPolicyOverride` RTBF event) and
`emit_outcome` both `tokio::spawn` a detached write whose only failure handling
is `warn!` (`registry/syncer.rs:222-246,459-490`). The RTBF override is a
privacy/compliance record; if the spawned write fails after the registry mutation
already happened, the audit trail silently misses it, and the cursor advances
independently so it isn't re-emitted.
**Change:** make `emit_override` await its write and fail the tick (or persist a
pending-audit marker) on error so it re-emits next walk; at minimum make the RTBF
override non-detached.
**Accept:** injecting an audit-write failure on the override path leaves state
such that the next tick re-emits rather than dropping it.

### P1.4 — Single token-mint path + AAL2 short-TTL parity; one holder-signature verifier (M)
**Problem:** `passkey_login_finish` (`routes/auth.rs:471-611`) can't reuse
`handle_authenticate_with_aal` (no `ChallengeSent` session) so it hand-rolls the
entire mint and sets the full ~15-min access TTL while stamping `aal2` — the
canonical handler deliberately mints aal2 tokens at
`access_token_ttl_for_aal2()` (1/3, min 60s) to bound a leaked elevated token,
and passkey login is the primary aal2 mint path, so the one token class that
hardening protects gets the longest exposure. It also emits no `Authenticated`
audit event. Separately, four copies of the Ed25519 domain-tagged
holder-signature verifier differ only by canonical struct + domain tag
(`submit.rs`, `accept.rs`, `status.rs`, `members/rotate.rs`).
**Change:** extract `mint_session_tokens(backend, did, role, contexts, amr, acr)`
in `vti-common` called by both the canonical handler and the passkey path
(computing the AAL2 TTL the same way), and emit the audit event there; extract one
generic `verify_domain_signed(did, domain_tag, payload, sig)` and route all four
sites through it.
**Accept:** passkey-login-finish yields `expires_in == access_token_ttl_for_aal2()`
and writes an `Authenticated` envelope; one signature verifier with all four
former sites delegating.

### P1.5 — Policy upload validates package/purpose match (S)
**Problem:** `upload` (`routes/policies/admin.rs:126-193`) compiles + stores under
the operator-declared `purpose` but never checks the module's package matches the
purpose's expected package (`vtc.join`/`vtc.removal`/`vtc.role_change`/
`vtc.directory`) or defines the expected rule. A mismatch compiles + activates
cleanly, then evaluates to `undefined` → silent host default-deny for that entire
ceremony — fails closed but is invisible: the operator sees a successful upload +
activate and a community that silently denies everything. `default.rs::yields_decision`
shows the host already knows how to probe this.
**Change:** in `upload`/`activate`, evaluate the purpose's canonical query against
a trivial input and reject if the module yields no decision/`allow`, naming the
expected package.
**Accept:** uploading a `purpose: join` policy whose package is `vtc.removal` is
rejected with a clear error.

**Checkpoint 1:** P1.1–P1.5 merged; e2e suite green; admin-UI config/profile
round-trips unchanged; cross-community recognise smoke unchanged.

---

## Phase 2 — Collapse the adapter shells & move logic out of routes

These assume P1.1 (single config surface) and P1.4 (shared helpers). Tests-before-
moves discipline applies.

### P2.1 — Move ceremony orchestration out of route handlers (L)
**Problem:** the full decide→resolve→effect→audit spines for join, leave, and
role-change live in `routes/` against the thin-adapter house style:
`submit_inner`/`decide_join`/`realize_join_verdict` (`submit.rs:155-323`),
`remove_inner` (`remove.rs:140-266`), `role_change_via_pipeline`
(`update.rs:167-240`). The clean `ceremony/*` pipeline modules exist, but the
per-ceremony wiring that belongs beside them is scattered through route files —
which is why the P0 audit-gap (auto-admit), dedup, and freshness fixes each land
in multiple places.
**Change:** move the orchestration functions into `ceremony/` (or `operations/`);
routes become thin adapters that extract auth + body and call them. Fold the
shared `MemberAdded`/`VmcIssued`/`VecIssued` audit emission (the auto-admit
under-audit gap, `submit.rs:218-313` vs `decide.rs:117-150`) into one helper used
by both the auto-admit and manual-approve paths.
**Depends:** P1.4.
**Accept:** route handlers contain no policy-load/decide/effect/audit logic; the
orchestration is unit-testable without axum; an auto-admit produces the same
audit envelopes as a manual approve.

### P2.2 — One facts-builder + cached member count (M)
**Problem:** four `Facts` builders (`assemble_*_facts` in `submit.rs:332-371`,
`remove.rs:288-363`, `update.rs:246-304`, `directory.rs:134-209`) repeat
community_did load + member_count scan + actor-role lookup + `MemberState`
construction with small per-purpose deltas. Each also computes `member_count` via
a full `members:` keyspace walk (`list_members(...).len()`) — on the
unauthenticated directory + join paths that's an O(members) scan per request.
**Change:** extract one `assemble_facts(purpose, actor, subject, evidence)` helper
in `ceremony/`; maintain a cached/persisted member counter (increment on admit,
decrement on purge) threaded through `Context`.
**Accept:** one facts-assembly helper; a directory query performs no full member
scan; ~150–200 LOC removed.

### P2.3 — Split `exchange.rs` (2,316 LOC) into four modules (L)
**Problem:** one file owns the OID4VCI issuer gate
(`verify_oid4vci_proof`/`issue_on_request`/`credential_offer`, `:50-232`), the
OID4VP verifier stack (`verify_presentation`/`verify_vp_token`/`verify_di_vp`/
`verify_bbs_presentation`/`DidVmResolver`, `:234-1045`), temporal/JWK/segment
helpers (`:1047-1131`), and the persisted pending-offer store
(`make_offer`/`redeem`, `:1133-1268`). Mirrors the VTA's `credential_exchange.rs`
split task.
**Change:** split into `exchange/{issue,verify,pending,jwt}.rs`, re-exported from
`exchange/mod.rs` so `credentials/mod.rs:58` is unchanged.
**Accept:** no public-path changes; `cargo test -p vtc-service` green; each new
file < ~700 LOC.

### P2.4 — One DID-VM → DI-proof verifier (M)
**Problem:** three copy-pasted "resolve verificationMethod → verify DI proof"
implementations: `DidResolverKeyResolver` + `verify_proof`
(`recognition/verify.rs:254-285,400-433`), `DidVmResolver`
(`exchange.rs:320-485`), and `relationships::verify_vc_proof`
(`routes/relationships.rs:290-329`). Three subtly-different copies of
security-critical key resolution (only `DidVmResolver` handles the bare-`did:key`
fast path; only `recognition` binds to `issuer_did`) — a divergence hazard.
**Change:** hoist one resolver into a shared module (`credentials::vm_resolver` or
`vti-common`) implementing both `VerificationMethodResolver` and the
`ForeignIssuerKeyResolver` trait; route `recognition` + `relationships` through it.
**Depends:** P2.3 (exchange split lands the canonical copy).
**Accept:** one resolver implementation; recognition/relationships tests still
pass; the issuer-binding check is centralized.

### P2.5 — Keyspace name registry; offline-CLI durability + parity (S)
**Problem:** keyspace-name string literals are re-typed across 7 non-test files
(`server.rs:199-224`, `main.rs:375-377`, `emergency.rs:248-250`,
`status.rs:201-202`, `acl_cli.rs`, `did_key.rs`, `setup/wizard.rs:1339-1356`).
The cost is real: the wizard's `open_keyspaces` (meant to pre-create partitions
so first `vtc start` is cheap) opens 8 of the daemon's ~21 and nobody noticed.
Separately, `run_invite_cli` (`main.rs:374-412`) and `run_emergency_bootstrap`
write an Admin ACL entry + install token and exit **without** `store.persist()`,
while `acl_cli`/`did_key` persist — the operator hands out a URL whose token row
may not be durable across a crash.
**Change:** `pub mod keyspaces` in `src/store/` with `const` names + `const ALL`;
`server.rs`, the CLIs, and `open_keyspaces` consume it (`open_keyspaces` iterates
`ALL`). Add `store.persist()` before printing the URL in `run_invite_cli` and at
the end of `run_emergency_bootstrap`.
**Accept:** `rg '\.keyspace\("' src` (excl. tests) shows only the constants
module; an `ALL.len()` test pinned to the AppState keyspace-field count; every
offline write path ends with `persist`.

### P2.6 — Per-feature routers + a posture-asserting test (L)
**Problem:** `routes/mod.rs` (1,202 LOC) declares every route, Trust-Task, body
cap, and (implicitly) auth gate inline in one function; per-method handlers
collapse onto a single Trust-Task (`members/{did}` GET+PATCH+DELETE share
`members/show/1.0`), so auth posture isn't locally legible — which is how the
P0.5 misplacement slipped in. No test enumerates routes and asserts each one's
(auth, rate-limit branch, body cap) triple.
**Change:** split into per-feature router builders each returning routes + a
static posture descriptor; add a `route_posture` test walking the assembled router
and asserting the full table. (This is the structural backstop for P0.5 — land
P0.5's fix first, then make regression impossible.)
**Accept:** the posture test fails if a route is added without declaring its auth
gate + branch; ~300–400 LOC net reduction once the repeated
`TrustTask::new(...).expect(...)` boilerplate is tabular.

### P2.7 — Three near-parallel registry files share an un-extracted fetch-verify-apply skeleton (M)
**Problem:** `upstream.rs` (HTTP transport), `syncer.rs` (dispatch/apply), and
`tail.rs` (audit→job) each independently encode the record lifecycle; `run_call`
and `update_mirror` (`syncer.rs:409-457`) duplicate the exact
`RegistryRecord::fresh_active`/`departed(... historical ? Some(now) : None)`
construction — a drift hazard.
**Change:** extract `RegistryRecord::for_job(&SyncJob) -> Option<RegistryRecord>`
consumed by both `run_call` and `update_mirror`.
**Accept:** single source of record-shape; the two no longer duplicate the
`historical` branch; ~60–100 LOC removed.

### P2.8 — Collapse the DTG credential builders (S)
**Problem:** `build_vmc`/`build_role_vec`/`build_custom_endorsement`/invitation
(`credentials/{vmc.rs:153-168,vec.rs:81-100,custom_endorsement.rs:106-155,
invitation.rs:36-73}`) each assemble params → call `dtg::issue_*` →
`serde_json::from_value` into `VerifiableCredential` with the same
`AppError::Internal` mapping; the params structs are 90% identical builder
boilerplate.
**Change:** one `dtg::finalize_typed() -> VerifiableCredential` helper for the
JSON→VC conversion; consider a single `CredentialParams { kind }`.
**Accept:** builders shrink to param-assembly + one call; builder unit tests
unchanged.

**Checkpoint 2:** adapter LOC reduction realized; wire behavior pinned by the
posture test + ceremony orchestration tests; `vtc-service/CLAUDE.md` source-layout
section updated to reflect new file sizes/locations.

---

## Phase 3 — Strategic convergence + hygiene (ongoing)

### P3.1 — Real host-based surface isolation (or honest docs) (L)
**Problem:** `host_dispatch` (`routing/host_dispatch.rs:77-119`) only does
allowlist membership, then routes by path across all mounts regardless of which
host matched — so `api.example.com/admin/...` still serves the SPA and
`admin.example.com/` still serves the public website. The config validator
*allows* admin-UI at `/` in "host mode" on the false premise that host mode
isolates (`routing_cors.rs:40-62`), and in default path mode the public website
and admin SPA share one origin with a `Path=/` session cookie, so
operator-deployed website JS (or stored XSS in marketing content) executes on the
admin origin and can call authenticated `/v1` endpoints riding the cookie
(`routes/mod.rs:1160-1190`, `auth.rs:623-636`, `csrf.rs:85-92` same-origin pass).
There is currently no deployment posture that actually isolates deployed website
content from the admin session.
**Change:** implement per-host surface routing (dispatch to a per-host sub-router
so a host exposes only its own surface) and make host separation the
required/forced posture when a filesystem website is configured; or scope the
admin session cookie under the admin mount and stop serving the public website on
the admin origin. Document in `website-and-admin.md`.
**Accept:** in host mode `GET admin.example.com/v1/...` and `api.example.com/admin`
both 404; a script deployed to `/` cannot make an authenticated `/v1/acl` call
with the admin cookie.

### P3.2 — CSRF: bearer exemption + tighten the exempt list (M)
**Problem:** `csrf::enforce` (`routing/csrf.rs:49-127`) requires same-origin or a
double-submit token on every mutating request not in `CSRF_EXEMPT_PATHS`, with
**no exemption for `Authorization: Bearer`** (structurally CSRF-immune), so
programmatic CLI/wallet clients get 403. The unauth holder endpoints
`accept`/`status` aren't exempt (only bare `/v1/join-requests` is, `csrf.rs:50`),
so the intended CLI/wallet holder is blocked while the browser flow passes.
**Change:** skip CSRF when an `Authorization: Bearer` header is present
(cookie-session requests stay gated); add the public join surface
(`accept`/`status`, or a prefix match) to the exempt set.
**Accept:** bearer POST with no Sec-Fetch/cookie passes; cookie-session POST with
no token → 403; CLI-style accept/status passes.
**Note:** the CSRF layer is attached in `server.rs` but not in the test `router()`,
so this break is invisible to CI today — wire CSRF into the integration harness as
part of this task.

### P3.3 — Website single-file `PUT` must use the same safety chain as deploy/serve (M)
**Problem:** `routes/website/files.rs:182-238` (`write`) doesn't call
`canonical_within_root` (only checks the parent), explicitly drops the executable
blocklist (`:228` `let _ = blocklist;`), and has no hidden/control-char/NFC check
— so an admin can `PUT /.htaccess`, `/evil.php`, `/.git/config` that `deploy` and
`serve` both reject. Worse, `create_dir_all` runs (`:216-219`) **before** the
escape check (`:230-238`), so `PUT .../../foo/bar/x` creates directories outside
the root before rejection (a pre-validation filesystem-mutation primitive,
admin-gated).
**Change:** route `write` through the full safety chain (blocklist, hidden,
control/NFC, canonical-within-root) **before** any `create_dir_all`; reject first,
create second.
**Accept:** `PUT .../evil.php` → 403; `PUT .../.hidden` → 400/404; `PUT
.../../escape` creates no directory and returns 400.

### P3.4 — Validate/clamp per-site CSP override; stop reading it per-request (S)
**Problem:** `read_csp_override` (`website/serve.rs:131-155`) reads
`<root>/.vtc-website.toml` on every request and emits its `csp` verbatim with no
validation, so an operator (or anyone with website write access) can set
`script-src 'unsafe-inline'` on an origin shared with the admin SPA (path mode),
neutralizing the default — plus a per-request disk stat/parse on the hot path.
**Change:** validate against a directive allowlist or refuse to weaken
`script-src`/`object-src`/`base-uri` below the daemon default; cache the parsed
override with the content-cache TTL. Tie to P3.1 so a relaxed website CSP can't
affect the admin origin.
**Accept:** an override that loosens `script-src` is rejected/clamped; the override
isn't parsed on every request.

### P3.5 — Cache-control + unauth-scan hygiene on the admin/website edge (S)
**Problem:** admin `index.html`/SPA-fallback is cached `public, max-age=300` like
hashed assets (`admin_ui.rs:116`), so after an upgrade a browser serves a stale
shell pointing at asset hashes the new binary dropped → broken SPA for up to 5
min. `GET /admin/plugins.json` is unauthenticated and re-scans `plugin_dir`
(readdir + read every manifest) on every request
(`routes/admin_ui.rs:101-188`) — an unauth disk-amplification lever. `serve`'s
doc claims `If-None-Match`→304 but never implements it (`serve.rs:24` vs
`:64-148`).
**Change:** serve `index.html`/SPA-fallback `no-cache`, keep the long TTL only for
content-hashed `/assets/*`; cache the plugin-manifest scan with a short TTL or
gate it behind auth; implement `If-None-Match`→304.
**Accept:** `/admin/` carries `no-cache`, `/admin/assets/<hash>.js` keeps the long
TTL; repeated `plugins.json` doesn't re-readdir every call; a conditional GET with
matching ETag → 304.

### P3.6 — Typed errors across the registry + DIDComm boundaries (S)
**Problem:** `RegistryError::{Transient,Permanent,Unreachable}` carries
retriable/permanent semantics but is documented as mapping all to
`AppError::Internal(String)` at the route boundary (`registry/client.rs:34-53`,
`storage.rs`), so `/v1/auth/recognise` returns the same opaque 500 for "registry
down" as for "internal bug" — against the house rule on preserving typed errors.
DIDComm handlers collapse every business outcome (forbidden/not-found/conflict/
malformed) into `DIDCommServiceError::Internal` (`messaging.rs:229-509`), so the
sender can't distinguish a malformed body from a real failure (and often gets no
reply).
**Change:** map `Unreachable`/`Transient` → 503, `Permanent` → 502/422; return
DIDComm problem-reports with proper codes for the 4xx-equivalent cases, reserving
`Internal` for true infra failures.
**Accept:** recognise against an unreachable registry → 503 not 500; a malformed
`join-request/submit` DIDComm body → a problem-report not a silent `Internal`.

### P3.7 — `/health` minimal liveness; gate infra detail (S)
**Problem:** `GET /health` (`routes/health.rs:33-51`, mounted at parent root
outside the governor) returns `vtc_did`, `vta_did`, `mediator_url`, `mediator_did`,
and the exact build version unauthenticated and unthrottled — a free
liveness/version/recon oracle; `did.jsonl` at root carries no `nosniff`.
**Change:** split a minimal `{status, version}` liveness payload (drop
`mediator_url`); fold the DID/mediator detail behind `AdminAuth` (the diagnostics
route is already admin-gated + governed); add `nosniff` to `did.jsonl`.
**Accept:** unauthenticated `/health` no longer returns `mediator_url`; detailed
identity fields require auth.

### P3.8 — Syncer cost + idempotency (M)
**Problem:** the syncer tail walk full-scans the entire `audit` keyspace every 5s
tick (`tail.rs:114` scans from an empty prefix, filters by timestamp) — cost grows
linearly with total audit history forever, becoming the daemon's dominant
steady-state cost. And `walk` enqueues jobs with a fresh UUID each and
`?`-propagates a mid-loop store error without advancing the cursor
(`tail.rs:163`, `syncer.rs:193-197`), so a partial-walk failure or a crash between
enqueue and cursor-write re-enqueues fresh-UUID duplicates on the next tick.
**Change:** seek the tail walk from the cursor key (`<cursor-rfc3339>:` lower
bound — note the store-layer needs a range/`from`-key API, not just
`prefix_iter_raw`); derive the `SyncJob` id from the audit `event_id` so a re-walk
overwrites rather than duplicates.
**Accept:** walk cost is proportional to new-rows-since-cursor; failing the Nth
store then re-walking ends with exactly one job per source envelope.

### P3.9 — No backup/restore story (XL — design note first)
**Problem:** the only export is `POST /v1/admin/config/export` (profile + config
overrides only, `routes/admin/config.rs:357-388`). Members, ACL, join requests,
endorsements, relationships, **status lists** (whose loss bricks every issued
VMC's `credentialStatus` URL), policies, and the audit log have no export/import
path. The VTA ships full encrypted backup/restore; the VTC — holding the
community's irreplaceable social state — has nothing. Disk loss = community loss.
**Change:** design note + port of the VTA backup pattern (iterate all keyspaces
from the P2.5 registry, Argon2id + AES-256-GCM, `vtc_did` compatibility check on
import mirroring `check_vta_did_compatibility`).
**Depends:** P2.5 (keyspace registry so the census can't silently omit a keyspace).
**Accept:** round-trip — populate every keyspace, export, wipe data dir, import,
daemon serves identical state; import onto a different `vtc_did` → 409. A
"keyspace census" test asserts export touches all of `keyspaces::ALL`.

### P3.10 — Non-interactive `vtc setup --from <toml>` (L)
**Problem:** `vtc setup` is TTY-only (`setup/wizard.rs` prompts at every step via
`dialoguer`); the crate's own CLAUDE.md claims a "from-TOML" path that doesn't
exist (misdirects operators + future agents). The VTA has `setup --from`. The
wizard's *effects* are already pure functions (`build_app_config`,
`write_did_log`, `write_config_toml`, `mint_initial_install_token`,
`run_provision_quietly`) — the missing piece is an inputs struct + a driver.
**Change:** `WizardPlan { inputs, webvh, secrets, messaging }`; `run_setup_wizard`
= `collect_interactive() → apply(plan)`; add `vtc setup --from <toml>` =
`parse(toml) → apply(plan)`. Fix CLAUDE.md either way.
**Accept:** `vtc setup --from fixture.toml` completes against a mock provision flow
with no TTY; CLAUDE.md matches reality.

### P3.11 — Emergency-bootstrap hardening (S)
**Problem:** the destructive recovery path
(`emergency.rs:248-328`) is a non-atomic multi-delete that clears `acl`/`passkey`
but leaves the `sessions` keyspace intact (refresh tokens for the presumed-
compromised admins survive), stamps the `EmergencyBootstrapInvoked` audit marker
*after* the clear (a mid-loop crash leaves the wipe unaudited), and relies on the
drop path to flush.
**Change:** stamp the pending-emergency audit marker *before* the destructive
loop; clear the `sessions` keyspace (all rows, or all for cleared DIDs); call
`store.persist()` before returning.
**Accept:** marker written before the first delete; a cleared admin's session row
is gone and stays gone after a cold reopen; a re-run after a simulated mid-loop
failure completes cleanly.

### P3.12 — Install `claim/finish` crash-safe delivery (S)
**Problem:** `finish_claim` (`routes/install.rs:180-297`) flips `Issued→Consumed`
(durable) at `:218`, then persists the passkey/AdminEntry, then mints + returns
the `setup_session_token`. A crash between consume and return permanently spends
the token but leaves the operator without the token needed by `/admin/bootstrap`
and no admin ACL entry — they must re-run setup. (Consume-first is the
security-correct direction; this is an availability sharp edge.)
**Change:** make `claim/finish` idempotent against a `Consumed` row within `exp` —
re-derive + re-mint the `setup_session_token` from the persisted
`admin_did`/passkey rather than hard-rejecting.
**Accept:** calling `claim/finish` twice for the same successful ceremony returns a
usable token both times; a `start→finish→start` sequence still rejects the second
`start`.

### P3.13 — Hygiene cleanups (M, several small PRs)
- **Stale webauthn doc** (`webauthn.rs:1-43`): the header claims "Ed25519-only /
  rejects non-EDDSA" but `finish_passkey_registration` does no such check and the
  start helper advertises ES256/RS256/EdDSA — rewrite to match the real posture.
- **Dead `b64:` inline-secret path** (`setup/bundle.rs:228-248`): exported +
  documented as the production path, zero callers; the wizard writes hex and
  `ConfigSecretStore::get` (`keys/seed_store/config.rs:22-30`) only hex-decodes,
  so a `b64:` value is unbootable. Either teach `get` the prefix + have the wizard
  use `inline_secret_for_bundle`, or delete the pair and fix the comments.
- **`Debug` derives on secret-bearing types** (`setup/bundle.rs:49` `VtcKeyBundle`,
  `config.rs:8` `SecretsConfig`): no current `{:?}` leak, but one future
  `debug!(?config)` leaks both signing keys — manual redacting `Debug` impls. The
  wizard prints the admin private key JSON to stdout (`wizard.rs:223-239`) — gate
  behind an explicit confirm, file the keyring follow-up.
- **`vtc create-did-key` mislabels fields** (`did_key.rs:48-62`): the credential
  bundle carries the VTC's DID/URL under `"vtaDid"`/`"vtaUrl"` (copy-paste) →
  rename to `vtcDid`/`vtcUrl` (check the consumer first).
- **Unbounded public profile fields** (`community/profile.rs:103-158`): no length
  caps on `name`/`description`/`logo_url`/`contact_email` (served on the unauth
  `/v1/community/public-profile`), no scheme check on `logo_url` (admin-only
  mutators, low sev) — cap + validate in `CommunityProfileUpdate::apply`.
- **Path-param DIDs as keyspace keys without validation** (`members/read.rs:165`,
  `remove.rs:106`, `update.rs:52`, `personhood.rs:145`, `directory.rs:83`):
  normalize/validate through `vti_common::identifier` before use as store keys.
- **`http://` registry URL accepted** (`registry/upstream.rs:92-108`): `new()`
  accepts any scheme → recognition answers trusted over cleartext, spoofable by an
  on-path attacker → reject non-https in `new()`. (Direction note: the recognition
  *read* should move to DIDComm when the upstream exposes it — house rule prefers
  authcrypt's intrinsic sender auth over bespoke REST+signature.)
- **Supervisor restart-on-panic** (`server.rs` spawns the syncer with bare
  `tokio::spawn`): a panicking syncer loop dies silently with no health signal —
  add restart-or-surface and reflect a dead syncer in diagnostics.

---

## Invariants any task must preserve (the do-not-break list)

Security/crypto:
- `LAST_ADMIN_LOCK` spans the no-last-admin check→write in `depart`/`remint`;
  extend the same discipline (P0.15) to `admit` and (P0.1) to status-list RMW.
- Issuer-key-binding enforced everywhere a proof is verified: SD-JWT `kid` base ==
  `iss`; DI VC proof VM under the VC `issuer`; BBS VM under issuer; status-list
  proof VM under the list's own issuer. Don't relax.
- Status-list substitution defense: `verify_status_list_signature` binds the
  fetched list's `issuer` to the credential's issuer and verifies the list's own
  DI proof before reading any bit.
- Decoy-slot allocator (#149 fix): `allocate` filters `!assigned && !is_set`;
  `flip` keeps `assigned[i]=true` so revoked slots are never reallocated; the
  `assigned` mask survives restart. The status-list serve route sets
  `Cache-Control: no-store` and never serves the `assigned` mask (occupancy masked
  by decoys) — preserve.
- Typestate `Verified*` discipline: `VerifiedPresentation`/`VerifiedFacts`/
  `VerifiedForeignCredential`/`ProvenHolderProof` only constructable via their
  verifiers; the evaluate stage only takes `&VerifiedFacts`; holder consistency
  across a multi-credential vp_token enforced. Add new wire forms this way.
- Host invariants enforced *around* Rego (`invariant::enforce` privilege-ceiling +
  step-up; the host `default_deny` backstop in `evaluate.rs`) so a policy edit
  can't escalate. `execute::apply` is the single state-mutating seam. Preserve.
- Fail-closed policy loading; `policy_skips_publish` fail-closed (a malformed
  registry policy skips publish rather than leaking the membership graph).
- Single-use + freshness: `present_challenge::consume` removes before the expiry
  check (single-use even when expired); `redeem` consumes only on success; install
  token single-use under `INSTALL_TOKEN_LOCK` with a non-consuming claim window;
  emergency-bootstrap marker consumed-on-read.
- Constant-time compares: challenge (`handlers/mod.rs:72`), Argon2id claim-secret
  verify, CSRF token (length-gate before `ct_eq`), audit actor-hash. Keep.
- Refresh tokens SHA-256-hash-indexed, atomic claim-and-delete, single-use
  rotation; `Session::Debug` redacts. Auth extractor checks server-side session
  state (existence + `Authenticated`) on every request — the revocation mechanism.
- JWT: EdDSA pinned, `aud="VTC"` enforced, required claims + exp checked,
  `aws_lc_rs` provider (no `rsa`). Audience isolation VTA↔VTC — no shared audience.
- RTBF disposition (`clamp_disposition`/`is_rtbf_purge`): clamp up to the
  preservation floor, but member self-purge (`actor == target && purge`) overrides
  the floor; the override audit envelope is emitted only when the clamp would have
  fired.
- Boot recovery: syncer `InFlight→Pending` flip on boot; persist `InFlight` before
  the network call.

Wire/compat:
- Stored-record evolution additive-only with least-privilege `#[serde(default)]`
  defaults; keyspace key encoding percent-encodes `:`/`/`/`%` to avoid prefix
  collisions (the relationships index P0.11 is the one that missed this).
- `deny_unknown_fields` on the auth TT response payloads and `CommunityProfileUpdate`
  (community_did deliberately immutable) — don't add fields.
- Typed `e.p.msg.forbidden` vs `unauthorized`; `suggested_fix` strings are the
  operator-UX contract.

Runtime topology:
- Single `AppState` construction (`server.rs:380`) shared by REST, DIDComm, and
  background tasks — VTC does NOT have the VTA's split-state bug; keep it that way
  (P1.1 fixes the *derived* boot-stable snapshots, not the Arc sharing).
- Listener bound once before threads; REST+DIDComm joined in parallel, storage
  joined last with `persist(SyncAll)`; panic in any thread triggers shutdown.
- Idempotent, non-clobbering boot heals (default policies, legacy-ceremony upgrade,
  status-list seed, missing-AdminEntry heal, profile heal) — loudly logged,
  preserve operator state.
- Router branch ⇒ posture: unauth crypto routes on the governed 64 KB branch (the
  P0.5 fix completes this); JWT routes off the limiter; CORS wildcard rejected at
  load, `allow_credentials` only with an explicit allowlist; admin-UI at `/`
  refused in path mode (cookie-scope guard) — reconcile with P3.1.
- Atomic website deploy/rollback: staging-dir + rename (live), symlink+rename swap
  (managed) — readers never see partial state.
- `website/paths.rs` traversal chain (NUL/control, NFC, hidden, blocklist,
  double-canonicalize containment, exec-bit) and `bundle.rs` zip-slip defense
  (pre-extract `verify_entries` + `Read::take(cap)`) are the reference — route the
  website `PUT` path through them (P3.3).
