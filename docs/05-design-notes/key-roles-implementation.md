# Key roles — implementation plan

**Status:** plan, step 0 of 13. **Paused** by the maintainer (2026-10-30): no
step starts without a go-ahead. The design itself — why, the model, benefits
and implications — is [key-roles.md](key-roles.md).

**Normative sources.** The VTI specification's *Key roles* chapter
(`spec/04-identity-keys.md`, dtgwg-vti-spec#79) and the method-neutral
`vta/dids/*` family (dtgwg-trust-tasks-tf#986): `vta/dids/_shared/0.1`
(`CONVENTIONS.md`, `key-roles.schema.json`, `method-profiles/`), `create`,
`update`, `keys/{list,add,rotate,retire,revoke}` and `recover`, all `1.0`. Where
this note and either disagrees, they are right and this note is the defect.

This note orders the work into reviewable PRs, maps each to the requirements it
satisfies and the Appendix F rows it closes, and records the decisions that are
ours to make (and the one that is not, §4).

---

## 1. Where the code stands

Read against Appendix F; every row below is *observed* there.

| Area | Today | Requirement it breaks |
|---|---|---|
| DID shape | `create_did_webvh` (`operations/did_webvh/mod.rs`) mints one Ed25519 key into `authentication` **and** `assertionMethod`, and uses that same key as the log's `updateKeys` | VTI-KEY-070/071/091/093, 146 |
| Fragments | Positional (`#key-0`, `#key-1`), kept across rotation | VTI-KEY-150 (SHOULD) |
| `keyRoles` | Absent everywhere | VTI-KEY-090, 095, 096 |
| Update keys | `vta_keys::derive_pre_rotation_keys` derives successors from the seed under the context base; handles only, re-derived on use | VTI-KEY-116 (must be generated) |
| Recovery key | None | VTI-KEY-116, 119, 128, 129 |
| Generated keys | `vta_keys::internal` generates from the CSPRNG and keeps keys in `internal_keys` (excluded from backup) — but protected only by the store key, which is HKDF of the seed (`hardened_bootstrap::derive_storage_key`, `vta_tee::kms_bootstrap::derive_storage_key`), or by nothing in plain mode. Ed25519 / P-256 only | VTI-KEY-118 |
| X25519 | `derive_entity_keys` and `Bip32Extension::derive_x25519` derive an Ed25519 key at the path and publish its birational image | VTI-KEY-184, CONVENTIONS §5.1 |
| Rotation | `update/rotate.rs` replaces every method at once, keeps ids, re-derives from the seed, no staging/overlap, nothing distinguishes rotation from compromise | VTI-KEY-120–127 |
| Passkeys | `operations/passkey_vms` enrols onto any VTA-minted `did:webvh` the caller administers, the VTA's own included, with no role | VTI-KEY-154, 155 |
| Approval | VTA step-up binds to a persona disclosure `previewId`; operation-bound step-up (`boundTo` digest) exists only in the VTC (`vtc-service/src/acl/bound_step_up.rs`); DTTE consent counts distinct approver DIDs | VTI-KEY-180–183 |
| Templates | `vta_sdk::did_templates` accepts `schemaVersion` 1–2 only; the VTA serves `vta/did-templates/*/3.1` | creation path (VTI-KEY-146–148) |
| Pins | `vta/webvh/dids/update/1.0` and `rotate-keys/1.0` vendored with the stale note "superseded by 2.x", hence two `#[allow(deprecated)]` in `trust_tasks/conformance.rs`. The registry now marks both live (deprecation `None`) because 2.x is retired | — |

What is kept: the derivation tree, key custody (`operations::key_custody`,
`vta_keys::custody`), the webvh log machinery (`didwebvh-rs`), the template
renderer, DTTE consent, the backup partition. Pre-role DIDs keep the
`vta/webvh/dids/*` tasks until they are replaced (CONVENTIONS §3.1).

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
3. **Role-key wrapping key (VTI-KEY-118).** Generated `attestation` and
   `update` keys are AES-256-GCM-wrapped under a *role-key KEK* that is random,
   not derived from the seed, and never in a backup:
   - **TEE:** a KMS data key whose release is bound to the enclave measurement,
     its ciphertext an environment-bound `bootstrap` row → `enclave`.
   - **Hardened / plain with a secret-manager seed backend:** a second secret
     in the same backend under its own name → `encryptedAtRest`.
   - **Plain with a config / plaintext seed backend:** a file beside the store,
     mode 0600 → `software`, and every preview warns `protectionBelowPolicy`.

   The KEK is held by a new `RoleKeyKek` door in `vta-key-roles`; the wrapped
   rows live in a new keyspace `role_keys` listed in `EXCLUDED_FROM_BACKUP`.
   A restore reports each lost role key (as `internal_keys` already does); the
   remedy is `vta/dids/recover`, never the backup (VTI-KEY-117).
4. **X25519 is derived as X25519** (VTI-KEY-184): 32 bytes HMAC-domain-separated
   at the role's own path and clamped, the same pattern `derivation.rs` already
   uses for P-256 and ML-DSA. The birational derivation stays only for the
   pre-role paths that published it, which keep working until replaced.
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
7. **The recovery key is an Ed25519 key** (webvh profile §9), carried as a
   `RecoveryCommitment` with its proof of possession: a signature over
   `vta-dids-recovery-commitment/v1 ‖ 0x00 ‖ previewId`. The VTA keeps only
   `hash(K)` and the label, never the public half once the commitment is
   computed. It refuses a key that matches any public key it holds (key
   records, role keys, webvh handles) — "a recovery key it generated, it always
   can" tell.
8. **Breaking changes are taken, not shimmed.** Old task versions stop being
   served where the family supersedes them; pre-role webvh tasks stay served for
   pre-role identities only and answer `unsupportedVersion` for a key-role one.

## 3. Steps

Each step is one PR against `main`, built on the previous one merged. "Closes"
means the Appendix F row is updated in step 13, citing the PR.

| # | PR | What | Requirements | Appendix F |
|---|---|---|---|---|
| 0 | `docs(design-notes)` | This note | — | — |
| 1 | `feat(vta)!` | **Pins and the eligibility gate.** Pin `vta/dids/*/1.0` and `vta/did-templates/{create,get,list,update}/3.2`; re-resolve `vta/webvh/dids/{update,rotate-keys}/1.0` to the registry's live bundles and delete both `#[allow(deprecated)]`. New crate `vta-key-roles` with `MethodProfile` (`webvh`, `scid:vh` eligible; `key`, `jwk`, `peer`, `web`, `webs` ineligible with `missing`; anything else: no profile), `methodNotEligible` with `details.missing`, and `methodParameters` validation against the profile's schema (`methodParameterUnsupported`). | VTI-KEY-170, 171, 172, 173 | — (none recorded) |
| 2 | `feat(key-roles)` | **The role model and the document.** The registry of CONVENTIONS §2.1 (role → relationship, origin, custody); a renderer from role keys to `verificationMethod`, relationships, top-level `keyRoles` (with the VTI-KEY-096 term in `@context`) and CID `revoked`; fragments derived from the key's multibase; the key-role-identity check (`notKeyRoleIdentity`), which refuses anything pre-role rather than guessing. `vta/webvh/dids/update/1.0` and `rotate-keys/1.0` answer `unsupportedVersion` for a key-role identity. | VTI-KEY-070–075, 090–096, 146, 147, 150 | KEY-090/092/094/095/096/150 (rendering half) |
| 3 | `feat(key-roles)!` | **The role-key store.** `role_keys` keyspace (excluded from backup, census updated), the role-key KEK of §2.3 per deployment, generation of Ed25519, P-256, ML-DSA-44/65 and X25519 role keys, `ProtectionClass` reported truthfully, `exportable: false`/`neverExportable`; `keys/export-secret` → `neverExportable`, `keys/set-exportability` → `notPermittedForThisKey`, `keys/revoke/0.1` → `boundToIdentifier`. Native X25519 derivation for `messaging`. Every door goes through `key_custody`; the census grows only by the store's one sanctioned load. | VTI-KEY-110, 112, 113, 116 (generated), 118, 184; CONVENTIONS §5.5 | KEY-110/118 |
| 4 | `feat(vta)!` | **Preview plans and preview-bound step-up.** `dids_plans` store, plan digest (payload minus `dryRun`/`previewId`/`recoveryProof`), `previewStale`, one outstanding plan per identity/role/caller, expiry sweeper that destroys pending keys; `stepUpRequired` carrying `details.stepUpRequest` (`boundTo` the salted digest of type + `previewId`) and `details.preview`; approve-response 0.7 marks the plan, never a session. Audit `did.keys.preview`, `did.keys.approval`. | VTI-KEY-180; VTI-APV-013; CONVENTIONS §6.1–6.3 | KEY-180 (half) |
| 5 | `feat(key-roles)` | **The recovery commitment.** `RecoveryCommitment` verification (PoP over the `previewId`), own-boundary refusal, webvh commitment `nextKeyHashes = [hash(R(n+1)), hash(K)]`, the carry-forward invariant enforced in the one function that builds a key-role log entry (a change that would drop or alter `hash(K)` fails to build unless it is a recovery entry or a quorum-approved replacement). SDK helper to sign a PoP; custodian CLI per §4. | VTI-KEY-116, 119, 128 (commit side) | KEY-116/119/128/129 (VTA half) |
| 6 | `feat(vta)!` | **`vta/dids/create/1.0`.** Template `schemaVersion` 3 (`keyRoles` layout of `RoleLayout`s, no key members) in `vta_sdk::did_templates`; serve `vta/did-templates/*/3.2` and stop serving 3.1; `templateNotKeyRole`; built-in key-role templates for a VTC, a VTN, a VTA and a persona; mint per role origin at preview time; render; commit routine successor and recovery key; apply atomically with every custodian record; publish (R2.1: publish, then commit the plan as applied; a crash between is resumed from the plan, never re-minted). Authorization §7 (`notFound` for an unreachable context). Audit `did.create` including refusals. | VTI-KEY-095, 096, 116, 119, 146–148, 150, 184; CONVENTIONS §4 | KEY-070/071/080/081/091/146 (creation path), KEY-093/113 |
| 7 | `feat(vta)` | **`keys/list`, `keys/add`, `vta/dids/update`.** Public vs custody projection (no `staged`/`retiring`, deadlines, custody or labels in public); `keys/add` for `attestation`/`operational`/`messaging` only (`notApplicableToRole` otherwise); non-key `update` with `methodParameters` (`UpdateParameters`, creation-fixed parameters refused). | VTI-KEY-103 (proof sets), 150; CONVENTIONS §7, §11 | — |
| 8 | `feat(vta)` | **`keys/rotate`.** Staged → active → retiring → retired with the cache horizon (`max(ttl, 24 h)`), `activatesAt`/`overlapUntil`/`autoRetire`, a scheduler for activation and auto-retire (`did.keys.activate`, `did.keys.autoRetire`), `rotationInProgress`, no algorithm substitution; `role: update` moves the routine authority with no overlap; `recoveryCommitment` replaces the commitment (gated by step 11's quorum; refused until it lands). | VTI-KEY-120, 122, 124, 125, 134, 184 | KEY-120–127 (rotation half) |
| 9 | `feat(vta)` | **`keys/retire` vs `keys/revoke`.** Retire removes the method and destroys retired `attestation`/`messaging` material (`did.keys.destroy`); revoke keeps it in `verificationMethod` with `revoked = compromisedSince`, out of every relationship and `keyRoles`, for life; emergency replacement in the same change from a fresh path (generated if the seed may be exposed); `compromiseTimeInFuture`; never blocked (supersedes a pending plan, recorded `aborted`); `role: update` with `scope: key` and `scope: boundary` (`awaitingRecoveryProof`, `RecoverySigningRequest`, `recoveryProofInvalid`); `followUp` for an attestation revocation. | VTI-KEY-120, 121, 123, 125, 126, 127, 128, 133, 182 (never blocked) | KEY-120–127 (revocation half), KEY-128 |
| 10 | `feat(vta)` | **`vta/dids/recover/1.0`.** Verify the supplied (or fetched) history as a resolver would; compute the single recovery entry (reveal K, new attestation + routine update keys, fresh routine successor and K′, lost attestation keys retired or — `mayBeExposed` — revoked); custodian proof; K is used once. | VTI-KEY-117, 128 | KEY-116/119/128 (recover) |
| 11 | `feat(vta)` | **Approvals floor.** `pendingApproval` with `KeyChangeApprovalState`; approve-requests bound to the same `previewId` to every eligible approver; the VTA applies itself at the count, under the initiator's authority; distinct VIDs, initiator once; quorum of two for replacing the recovery commitment (where two eligible approvers exist), SHOULD-two for attestation and routine update as policy; revocation never more than one; only the approver's own evidence — no delegated key, no key of the identity being changed, no node key. Rules expressed in the existing approvals row (`vta-policy`), floor enforced in code so a rule cannot go below it. | VTI-KEY-180, 181, 182, 183 | KEY-180–183 |
| 12 | `feat(vta)!` | **Passkeys are `authenticator` keys; clients.** Passkey enrolment only on a persona identity (a persona binding, `vta-persona`), never the VTA's own, a VTC/VTN or an integration; on a key-role persona it is bound to `keyRoles.authenticator`; `keys/revoke` may remove one. SDK `VtaClient` methods for the whole family, `pnm dids …` and `cnm dids …`, with errors that name the fix (`notKeyRoleIdentity` → "create a new identity"). | VTI-KEY-154, 155 | KEY-154 |
| 13 | spec PR (dtgwg-vti-spec) | **Appendix F.** Move each row above to *implemented* (or narrow it) with the PR numbers; record any divergence the steps left. | — | all of the above |

Order rationale: 1–3 are foundations with no wire surface beyond the refusal;
4 and 5 are the two disciplines every mutating task needs (a preview to bind to,
a recovery commitment to carry), so they land before the first task that
mutates (6). 8–10 follow the lifecycle. 11 is after the tasks so its floor is
tested against real plans; until it lands, the one change it uniquely gates
(replacing the recovery commitment) is refused rather than allowed with one
approval. 12 last because it changes a deployed flow (passkey enrolment onto
any DID) and needs the persona predicate settled.

## 4. Decided — how an operator supplies the recovery key

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
  no recovery commitment ⇒ refused; unknown method ⇒ no profile ⇒ refused;
  unknown `ProtectionClass` ⇒ `software` + warning.
- **ACL scope** read through `act_scope()`, never `allowed_contexts.is_empty()`.
- **No private key material** in any response or `ext`, in plans, or in audit
  `detail`.
