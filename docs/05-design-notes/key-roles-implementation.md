# Key roles — implementation plan

**Status:** plan, step 0 of 15. **Paused** by the maintainer (2026-10-30): no
step starts without a go-ahead. Revised the same day for key assurance levels
(dtgwg-vti-spec#82, dtgwg-trust-tasks-tf#993, both drafts): single-key
DIDs stay conformant as level 1, level 2 needs no recovery key, identities are
raised in place, and a FROST threshold custodian is added. The design itself —
why, the model, benefits and implications — is [key-roles.md](key-roles.md).

**Normative sources.** The VTI specification's *Key roles* chapter
(`spec/04-identity-keys.md`, dtgwg-vti-spec#79) and the method-neutral
`vta/dids/*` family (dtgwg-trust-tasks-tf#986, revised in #993):
`vta/dids/_shared/0.1` (`CONVENTIONS.md`, `key-roles.schema.json`,
`method-profiles/`), `create/1.1`, `upgrade/1.0`, and `update`,
`keys/{list,add,rotate,retire,revoke}` and `recover` at `1.0`. Where this note and
either disagrees, they are right and this note is the defect.

This note orders the work into reviewable PRs, maps each to the requirements it
satisfies and the Appendix F rows it closes, and records the decisions that are
ours to make (and the one that is not, §4).

---

## 1. Where the code stands

Read against Appendix F; every row below is *observed* there.

| Area | Today | Requirement it breaks |
|---|---|---|
| DID shape | `create_did_webvh` (`operations/did_webvh/mod.rs`) mints one Ed25519 key into `authentication` **and** `assertionMethod`, and uses that same key as the log's `updateKeys` | Conformant as level 1 (VTI-KEY-146); misses the SHOULD of VTI-KEY-196 (level ≥ 2 for a VTA, VTC, VTN) |
| Fragments | Positional (`#key-0`, `#key-1`), kept across rotation | VTI-KEY-150 (SHOULD) |
| `keyRoles`, `keyAssurance` | Absent everywhere | VTI-KEY-090, 095, 096, 197, 198 at level 2 and 3; nothing at level 1 |
| Update keys | `vta_keys::derive_pre_rotation_keys` derives successors from the seed under the context base; handles only, re-derived on use | Fine at level 2; VTI-KEY-116 (generated) at level 3 |
| Recovery key | None | VTI-KEY-116, 119, 128, 129, 205 — level 3 only |
| Generated keys | `vta_keys::internal` generates from the CSPRNG and keeps keys in `internal_keys` (excluded from backup) — but protected only by the store key, which is HKDF of the seed (`hardened_bootstrap::derive_storage_key`, `vta_tee::kms_bootstrap::derive_storage_key`), or by nothing in plain mode. Ed25519 / P-256 only | VTI-KEY-118 — level 3 only |
| X25519 | `derive_entity_keys` and `Bip32Extension::derive_x25519` derive an Ed25519 key at the path and publish its birational image | VTI-KEY-184, CONVENTIONS §5.1 |
| Rotation | `update/rotate.rs` replaces every method at once, keeps ids, re-derives from the seed, no staging/overlap, nothing distinguishes rotation from compromise | VTI-KEY-120–127 |
| Passkeys | `operations/passkey_vms` enrols onto any VTA-minted `did:webvh` the caller administers, the VTA's own included, with no role | VTI-KEY-154, 155, 191 (persona marks `authenticator`) |
| Approval | VTA step-up binds to a persona disclosure `previewId`; operation-bound step-up (`boundTo` digest) exists only in the VTC (`vtc-service/src/acl/bound_step_up.rs`); DTTE consent counts distinct approver DIDs | VTI-KEY-180–183 |
| Templates | `vta_sdk::did_templates` accepts `schemaVersion` 1–2 only; the VTA serves `vta/did-templates/*/3.1` | creation path (`create/1.1`, `upgrade/1.0`) |
| Verifiers | No verifier establishes a signer's level or applies a per-use minimum | VTI-KEY-199, 200, 201 |
| Pins | `vta/webvh/dids/update/1.0` and `rotate-keys/1.0` vendored with the stale note "superseded by 2.x", hence two `#[allow(deprecated)]` in `trust_tasks/conformance.rs`. The registry now marks both live (deprecation `None`) because 2.x is retired | — |

What is kept: the derivation tree, key custody (`operations::key_custody`,
`vta_keys::custody`), the webvh log machinery (`didwebvh-rs`), the template
renderer, DTTE consent, the backup partition. Level-1 DIDs keep the
`vta/webvh/dids/*` tasks, and the method-specific creation, until they are
raised (CONVENTIONS §3.1). Nothing existing has to change for the specification
to be met at level 1.

## 2. Decisions

1. **One new subsystem crate, `vta-key-roles`** (layer 2: `vta-sdk`,
   `vti-common`, `vta-keyspaces`, `vta-keys`). It holds what is method-neutral
   and pure: method profiles, the role registry, the document renderer, the
   key-role-identity check, the role-key store, preview plans and the recovery
   commitment. It is a subsystem, not spine, so it is inside the line
   `vta-service-decomposition.md` draws. Orchestration (the handlers, the
   webvh log append, publication) stays in `vta-service/src/operations/dids/`.
   Wire types are the generated `vta_sdk::specs::vta::dids::*`; nothing is
   hand-written.
2. **The webvh profile is the only eligible profile implemented.**
   `did:scid:vh` rides it (same log). `did:key`, `did:jwk`, `did:peer`,
   `did:web` and `did:webs` get profiles that say *ineligible* and the criteria
   missing, so the refusal is a statement (CONVENTIONS §18), not a fall-through.
3. **Role keys by level.** At **level 2**, `attestation` and `update` keys are
   **derived** from the seed under the context base, at role paths of their own
   (VTI-KEY-110 permits it): no new storage, no KEK, and a restore brings them
   back with no extra step. At **level 3** (VTI-KEY-118), they are generated and
   AES-256-GCM-wrapped under a *role-key KEK* that is random, not derived from
   the seed, and never in a backup:
   - **TEE:** a KMS data key whose release is bound to the enclave measurement,
     its ciphertext an environment-bound `bootstrap` row → `enclave`.
   - **Hardened / plain with a secret-manager seed backend:** a second secret
     in the same backend under its own name → `encryptedAtRest`.
   - **Plain with a config / plaintext seed backend:** a file beside the store,
     mode 0600 → `software`, and every preview warns `protectionBelowPolicy`.

   The KEK is held by a new `RoleKeyKek` door in `vta-key-roles`; the wrapped
   rows live in a new keyspace `role_keys` listed in `EXCLUDED_FROM_BACKUP`.
   A restore reports each lost level-3 role key (as `internal_keys` already
   does); the remedy is `vta/dids/recover`, never the backup (VTI-KEY-117).
4. **X25519 is derived as X25519** (VTI-KEY-184): 32 bytes HMAC-domain-separated
   at the role's own path and clamped, the same pattern `derivation.rs` already
   uses for P-256 and ML-DSA. The birational derivation stays only for the
   level-1 paths that published it, which keep working until raised.
5. **Preview plans are first-class rows** (`dids_plans` keyspace, excluded from
   backup: a plan does not survive a restore, and its pending keys are
   destroyed). A plan holds the canonical request digest, the base version, the
   pending key handles, the resulting document and its expiry (default 1 h). A
   sweeper expires them and destroys pending generated keys.
6. **Bound step-up is ported from the VTC, not reinvented.**
   `vtc-service/src/acl/bound_step_up.rs` already does refuse →
   `details.stepUpRequest` (approve-request 0.5 with `boundTo`) →
   approve-response 0.7 → mark → redeem. The digest helper moves to
   `vti-common` (it is already `task_consent::domain_digest`); the VTA binds to
   `(type URI, previewId)` under a new domain tag `vta/dids/step-up/v1\0`. A
   session elevation never satisfies it (VTI-KEY-180).
7. **The recovery key (level 3 only) is an Ed25519 key** (webvh profile §9),
   carried as a `RecoveryCommitment` with its proof of possession: a signature
   over `vta-dids-recovery-commitment/v1 ‖ 0x00 ‖ previewId`. The VTA keeps only
   `hash(K)`, the label and the declared `custodian` kind, never the public half
   once the commitment is computed, and renders `hash(K)` as
   `keyAssurance.recoveryCommitment`. It refuses a key that matches any public
   key it holds (key records, role keys, webvh handles) — "a recovery key it
   generated, it always can" tell. A threshold group's key is an ordinary
   Ed25519 key here.
8. **Breaking changes are taken, not shimmed.** Old task versions stop being
   served where the family supersedes them (`create/1.0` → `1.1`); level-1 webvh
   tasks stay served for level-1 identities only and answer `unsupportedVersion`
   for a key-role one.
9. **Level determination is one function, in `vta-sdk`.** VTI-KEY-199's cap
   (declared level, capped by `keyRoles`, the recovery commitment's presence in
   `nextKeyHashes`, witnessing, and a fall in the history ⇒ level 1) is a pure
   function over a resolved document and its log, used by every verifier we
   ship and by the VTA itself before a raise or a recovery. The per-use minimum
   (VTI-KEY-200) is configuration, with a default of 1 so that nothing that works
   today stops working.
10. **Custodians in order of cost.** A separately held key (`pnm recovery-key`,
    decided — §4) first; a second VTA after `recover` lands, since it reuses the
    same `RecoverySigningRequest` sent by DIDComm/TSP instead of out of band; the
    FROST threshold custodian last, only after its ceremony tasks
    (`vta/threshold/*`, CONVENTIONS §19) are specified, over an audited FROST
    implementation (the Zcash Foundation's `frost-ed25519`, RFC 9591), never a
    hand-rolled one.

## 3. Steps

Each step is one PR against `main`, built on the previous one merged. "Closes"
means the Appendix F row is updated in step 13, citing the PR.

| # | PR | What | Requirements | Appendix F |
|---|---|---|---|---|
| 0 | `docs(design-notes)` | This note | — | — |
| 1 | `feat(vta)!` | **Pins and the eligibility gate.** Pin `vta/dids/create/1.1`, `vta/dids/upgrade/1.0`, the rest of `vta/dids/*/1.0` and `vta/did-templates/{create,get,list,update}/3.2`; re-resolve `vta/webvh/dids/{update,rotate-keys}/1.0` to the registry's live bundles and delete both `#[allow(deprecated)]`. New crate `vta-key-roles` with `MethodProfile` (`webvh`, `scid:vh` eligible; `key`, `jwk`, `peer`, `web`, `webs` ineligible with `missing`; anything else: no profile), `methodNotEligible` with `details.missing`, and `methodParameters` validation against the profile's schema (`methodParameterUnsupported`). | VTI-KEY-170, 171, 172, 173 | — (none recorded) |
| 2 | `feat(sdk)` | **Levels, for verifiers.** The `KeyAssuranceLevel` type, `keyAssurance` parsing, and VTI-KEY-199's level determination over a resolved document and its log, in `vta-sdk`; a per-use minimum (VTI-KEY-200) in verifier configuration, default 1; VTI-KEY-201 (judge an artefact by its key's level). Persona documents: `keyRoles.authenticator` read, every other key by relationship (VTI-KEY-191). No behaviour changes at the default. | VTI-KEY-191, 197–201 | — |
| 3 | `feat(key-roles)` | **The role model and the document.** The registry of CONVENTIONS §2.1 (role → relationship, origin by level, custody); a renderer from role keys to `verificationMethod`, relationships, top-level `keyRoles` and `keyAssurance` (with the VTI-KEY-096 and VTI-KEY-198 terms in `@context`) and CID `revoked`; fragments derived from the key; the key-role-identity check (`notKeyRoleIdentity` for level 1, never a guess). `vta/webvh/dids/update/1.0` and `rotate-keys/1.0` answer `unsupportedVersion` for a key-role identity. | VTI-KEY-070–075, 090–096, 197, 198, 150 | KEY-150 (rendering half) |
| 4 | `feat(vta)!` | **Preview plans and preview-bound step-up.** As before: `dids_plans` store, plan digest, `previewStale`, one outstanding plan per identity/role/caller, expiry sweeper that destroys pending keys; `stepUpRequired` with `details.stepUpRequest` bound to type + `previewId`; approve-response 0.7 marks the plan. Step-up policy by level (§6.5: SHOULD for a level-2 create). | VTI-KEY-180; VTI-APV-013; CONVENTIONS §6.1–6.3 | KEY-180 (half) |
| 5 | `feat(key-roles)!` | **Role keys by level.** Level 2: derived at role paths, in the backup, `inBackups: true`, `exportable: false` except by backup. Level 3: `role_keys` keyspace (excluded from backup, census updated), the role-key KEK of §2.3 per deployment, generation of Ed25519, P-256, ML-DSA-44/65 and X25519 role keys, `ProtectionClass` reported truthfully, `neverExportable`. Both: `keys/export-secret` → `neverExportable`, `keys/set-exportability` → `notPermittedForThisKey`, `keys/revoke/0.1` → `boundToIdentifier`; native X25519 for `messaging`; every door through `key_custody`. | VTI-KEY-110, 112, 113, 116 (origin), 118, 184; CONVENTIONS §5.5 | KEY-110/118 |
| 6 | `feat(key-roles)` | **The recovery commitment (level 3).** `RecoveryCommitment` verification (PoP over the `previewId`), `custodian` recorded in custody only, own-boundary refusal, webvh commitment `nextKeyHashes = [hash(R(n+1)), hash(K)]` with `keyAssurance.recoveryCommitment = hash(K)`, the carry-forward invariant in the one function that builds a key-role log entry, the witness requirement (`witnessRequired`). SDK helper to sign a PoP; `pnm recovery-key` per §4. | VTI-KEY-116, 119, 128 (commit side), 129, 205 | KEY-116/119/128/129 (VTA half) |
| 7 | `feat(vta)!` | **`vta/dids/create/1.1` and `vta/dids/upgrade/1.0`.** Template `schemaVersion` 3 in `vta_sdk::did_templates`; serve `vta/did-templates/*/3.2`; `templateNotKeyRole`; built-in key-role templates for a VTC, a VTN, a VTA and a persona; `assuranceLevel` 2 or 3; mint per role origin and level at preview time; render; commit; apply atomically; publish (R2.1). `upgrade`: fresh keys for every tightened role, `previousKeys` retire/revoke, new routine authority, `keyAssurance`, refuse a non-raise (`assuranceLevelMismatch`), re-sign status lists, `followUp`. Audit `did.create`, `did.upgrade`. **Level 2 is reachable from here.** | VTI-KEY-095, 096, 116, 119, 146–149, 150, 184, 197; CONVENTIONS §3.5, §4 | KEY-196 row (creation and raise paths) |
| 8 | `feat(vta)` | **`keys/list`, `keys/add`, `vta/dids/update`.** As before, plus `assuranceLevel` in `keys/list` and `keyAssurance` refused in `update` (`keyMembersManaged`), witness removal at level 3 refused. | VTI-KEY-103, 150; CONVENTIONS §7, §11 | — |
| 9 | `feat(vta)` | **`keys/rotate`.** As before, plus: `recoveryCommitment` level 3 only; replacement authorized by the current recovery key (`useRecoveryKey`, `awaitingRecoveryProof`, `recoveryProof`), the quorum path only for a lost key (gated by step 12; refused until it lands). | VTI-KEY-120, 122, 124, 125, 134, 181, 184 | KEY-120–127 (rotation half) |
| 10 | `feat(vta)` | **`keys/retire` vs `keys/revoke`.** As before; `scope: boundary` level 3 only (`assuranceLevelMismatch` below it, with the deactivate-and-replace instruction). | VTI-KEY-120, 121, 123, 125, 126, 127, 128, 133, 182 | KEY-120–127 (revocation half), KEY-128 |
| 11 | `feat(vta)` | **`vta/dids/recover/1.0`** (level 3 only). As before; establish the level before recovering; route a `RecoverySigningRequest` to a `vta` custodian's DID by DIDComm/TSP where declared. | VTI-KEY-117, 128 | KEY-116/119/128 (recover) |
| 12 | `feat(vta)` | **Approvals floor.** As before, with the revised VTI-KEY-181: two approvers for a lost-key replacement and for a raise to level 3; none beyond the custodian's proof for a recovery-key-authorized replacement. | VTI-KEY-180, 181, 182, 183 | KEY-180–183 |
| 13 | `feat(vta)!` | **Passkeys are `authenticator` keys; clients.** Enrolment only on a persona, bound in `keyRoles.authenticator` (the persona's only `keyRoles` entry); `VtaClient` methods for the family; `pnm dids create --level`, `pnm dids upgrade`, `cnm dids …`, with errors that name the fix (`notKeyRoleIdentity` → "raise it with `dids upgrade`, or create a new identity"). | VTI-KEY-154, 155, 191 | KEY-154 |
| 14 | spec PR (dtgwg-vti-spec) | **Appendix F.** Move each row to *implemented* (or narrow it) with the PR numbers. | — | all of the above |
| 15 | `feat(...)` | **Second-VTA and FROST custodians** — deferred until the `vta/threshold/*` ceremony tasks are specified (CONVENTIONS §19). A crate over `frost-ed25519` (RFC 9591): dealerless DKG with transcript agreement, signing with single-use in-memory nonces, identifiable abort, refresh, liveness; shares in the excluded keyspace under the level-3 KEK; the VTI-KEY-211 boundary rules checked at group formation (no ACL subject approving at t participants). | VTI-KEY-206, 210–221 | KEY-205 row (custodian kinds) |

Order rationale: 1–3 are foundations with no wire surface beyond the refusal;
level determination (2) comes first among them because every verifier can use
it at once and it changes nothing for level 1. 4 and 5 are the two disciplines
every mutating task needs (a preview to bind to; at level 3, a recovery
commitment to carry), so they land before the first task that mutates (6).
Level 2 is reachable at step 7 — create and raise — without any level-3
machinery, which is the cheapest useful milestone: from there a VTC can stop
holding the key that signs its credentials. 9–11 follow the lifecycle. 12 is
after the tasks so its floor is tested against real plans; until it lands, the
quorum path for replacing a lost recovery key is refused rather than allowed with
one approval (the recovery-key-authorized path does not need it). 13 changes a
deployed flow (passkey enrolment onto any DID) and needs the persona predicate
settled. 15 waits on specifications that do not yet exist.

## 4. Decided — how an operator supplies the recovery key

(Level 3 only. A level-2 identity has no recovery key. This is custodian kind
(a), a separately held key; kinds (b) and (c) are step 15.)

The specification fixes *what* (an Ed25519 key in another protection boundary,
proof of possession over the `previewId`) but not *how an operator gets one*.
Decided by the maintainer on 2026-10-30, as proposed (see also [key-roles.md](key-roles.md) §5.2 for why the VTA's own BIP-32 seed cannot hold it):

- A custodian command, `pnm recovery-key {generate,show,sign-commitment,sign-recovery}`,
  that keeps the key **outside the VTA's host and config**: a passphrase-encrypted
  file (Argon2id + AES-256-GCM, the backup's KDF) written where the operator
  says, printed as a `did:key` and a digest to record; no default location
  under the VTA's data directory, and a refusal if pointed at one.
- `pnm dids create` runs the dry run, prints the `previewId` and the exact
  string to sign, and accepts the PoP back (`--recovery-key did:key:… --recovery-pop …`),
  so the custodian can be an air-gapped machine, a second operator, or (later)
  a hardware token via the same two flags. When the key file is local and the
  operator passes `--recovery-key-file`, the CLI signs in-process as a
  convenience.
- Hardware tokens (PIV / FIDO2 hmac-secret) are out of scope for the first
  cut; the two-flag form leaves room for them.

## 5. Security review checklist (every step)

- **Key custody.** No caller-chosen derivation path or key id reaches key
  material; role keys are reached only through the role-key store door; every
  refusal is audited (`key.custody_violation` / `did.*` with outcome `denied`)
  and logged `security_alert = true`. `key_custody_census` changes only with a
  stated reason.
- **R2.1 Remote-First.** A plan is marked applied only after the method's
  artefact is durable (published, or written for a serverless DID); a crash
  between resumes from the plan; pending keys are never re-minted for the same
  plan.
- **`deny_unknown_fields`** on every security-relevant body we own (plans,
  role-key rows, CLI inputs); generated wire types already carry
  `additionalProperties: false`.
- **Absence is most restrictive.** No layout role ⇒ refused, not defaulted;
  no recovery commitment at level 3 ⇒ refused; no declared level ⇒ level 1;
  a level that falls ⇒ level 1; unknown method ⇒ no profile ⇒ refused;
  unknown `ProtectionClass` ⇒ `software` + warning.
- **ACL scope** read through `act_scope()`, never `allowed_contexts.is_empty()`.
- **No private key material** in any response or `ext`, in plans, or in audit
  `detail`.
