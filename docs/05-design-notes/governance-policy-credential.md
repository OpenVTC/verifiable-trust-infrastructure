# Governance policy as a credential — closing #804 with zero new tasks

**Status:** design for review — implementation deliberately deferred pending sign-off. Written against #804 (V2, adopted by the Cierge side on 2026-07-26), having read the `vta/credentials/*` handlers, the VTC status-list producer, and the registry's `policy/*`, `vtc/endorsements/*` and `credential-exchange/*` families. Companion registry PR: trustoverip/dtgwg-trust-tasks-tf#157.

**Scope boundaries, as #804 draws them.** #805 confirmed the VTA enforces per-key access on sign — that property is orthogonal to this note and assumed. #817 established that no authorization refinement can distinguish a compromised multi-tenant gateway from an honest one; this note does not claim otherwise. What V2 removes is narrower and real: the ability to fabricate *what the rules were*. The witness residual — a compromised gateway lying about what passed through it — is irreducible and stays with #817's remedies.

---

## The gap, restated

Cierge's gateway attaches a governance attestation to LLM traffic, but the policy it enforces — model allowlist, budget cap, upstream pin, privacy tier — arrives from a TOML file on the gateway host. An attestation citing "policy P" has no referent any party other than that host agreed to. A TEE attests the code, not the inputs; `VtaClient::sign` (`vta-sdk/src/client/keys.rs:97`, enforced in `vta-service/src/operations/keys.rs`) is a blind oracle that endorses whatever bytes arrive. The fix #804 asks for: the VTA issues the domain's governance policy as a verifiable credential — issuance, revocation, distribution — so an attestation cites `policyHash` and a verifier checks *this hash is a policy the VTA issued for this domain and has not revoked*.

**The design constraint that shaped everything below: everything rides defined trust tasks with defined specs, and the new-task count is minimized.** The recommended shape adds **zero** new tasks.

## Option A — `vta/credentials/issue` + `revoke` with a claims profile *(recommended)*

The registry already has the issuance pair, and the VTA already implements it: `vta-service/src/trust_tasks/credentials.rs` (`handle_issue`, `handle_revoke`), minting in `vta-service/src/operations/credentials.rs` (unsigned W3C VC → `DataIntegrityProof::sign` with the VTA's `{vta_did}#key-0` assertion key). `payload.claims` is deliberately opaque and `credentialType` is a free string — so a **claims profile** is the natural, additive extension point: when `credentialType` is `GovernancePolicyCredential`, `claims` must satisfy a declared shape over `{domain, contextId?, policy, policyHash, policyMediaType?}`, where `policy` is the *complete* governing parameter document and `policyHash` is a multihash over its JCS canonicalization, recomputed by the VTA before minting.

Three properties fall out for free:

1. **The step-up gate is a feature, not friction.** `vta/credentials/issue` requires operator step-up. Per #817, the only mechanisms that survive a compromised caller are "don't give one process the credential" or "require a factor the attacker cannot supply". Policy rotation is rare and high-stakes — exactly where an out-of-band operator factor is *right*, in contrast to the per-request consent #817 correctly rejects for a gateway attesting every proxied call. A compromised gateway cannot rotate its own rules.
2. **Revocation exists** (`vta/credentials/revoke`, `IssuedCredentialRecord.revoked_at` in the `issued_credentials` keyspace, `vta-keyspaces/src/lib.rs:83-87`) — though its visibility needs the Option C mechanic below.
3. **The audit story exists** — `credentials.issue` / `credentials.revoke` audit events already fire.

What the profile adds on top (all draft-additive in the registry): a `profileViolation` error code, a **single-active rule** — at most one live `GovernancePolicyCredential` per `(contextId, domain)`; issuing a successor atomically revokes the predecessor and returns it as `supersedes`, mirroring `policy/activate`'s `previousPolicyId` — and a mandatory published `credentialStatus`.

## Option B — piggyback on `policy/activate` *(rejected)*

The `policy/*` family looks adjacent — upsert/activate/active already model a policy lifecycle with single-active-per-slot semantics. Could activation also mint the credential, making the VC a side effect of an existing task? Three reasons no:

1. **Wrong artifact.** A registry `PolicyModule` *is Rego source* — a decision policy the PDP evaluates against `PolicyInput` to gate task dispatch (`vta-policy/src/types.rs`). Cierge's governance policy is structured enforcement *parameters* the gateway must load. Carrying it as a `PolicyModule` would force the enforcing component to parse Rego to extract an allowlist — precisely violating #804's consumption requirement ("loads policy **out of** the credential").
2. **Wrong surface.** The VTA binds no `policy/*` task today — the canonical `spec/policy/*` URIs are bound only in `vtc-service` (`vtc-service/src/routes/mod.rs:770-800`), where `purpose` slots are community-governance stages (join, removal, …). Option B means implementing an entire task family on the VTA to obtain a side effect of one of them.
3. **Not additive.** `policy/activate/0.1` declares its side effects as an atomic pointer swap, reversible via `previousPolicyId`. Minting a signed, distributable credential is a materially different consequence set — that is a breaking contract change to a shipped spec, versus a claims profile that leaves `vta/credentials/issue`'s declared semantics untouched.

What Option B *does* contribute is its supersession model: the single-active-per-slot rule and displaced-id auditability are adopted into the profile.

## Option C — the `vtc/endorsements` pattern *(adopt the mechanics, not the family)*

`vtc/endorsements/issue`/`revoke` is the registry's typed-credential-with-published-revocation pattern: a status-list slot allocated at mint, revocation as a bit flip on a published Bitstring Status List, the slot never reclaimed. The family itself is the wrong home — it lives on the community self-management plane, gated by community ACLs and a registered endorsement-type registry; the governance-policy issuer is the domain's VTA on the management plane.

But its **revocation distribution model is exactly right**, because the verifier of an attestation is a third party. Today the VTA records revocation as a field on a stored record — visible only to callers of the VTA. The alternative to a published bit would be a new "is credential X revoked?" read task for strangers — i.e. a *new task*, and an availability coupling on every verification. A `credentialStatus` entry pointing at a published status list keeps the entire verification chain in standard VC machinery, **outside task-space entirely**. So the profile mandates `credentialStatus`, and `vta/credentials/revoke` gains the bit-flip obligation (and a confirming `statusListIndex` in its response) for profile credentials.

`vtc/endorsements/issue`'s own "why this is not `vta/credentials/issue`" argument (no published bit on VTA shares) is not contradicted: the promise attaches to the `credentialType`, not the task URI — untyped shares keep their consult-the-VTA semantics.

## Distribution — an existing read already fits

#804's third ask is "a way for the enforcing component to fetch the current credential for a domain it serves". Candidates, cheapest first:

| Mechanism | Verdict |
|---|---|
| `credential-exchange/query` → `present` — gateway as verifier, VTA as holder of the profile credentials it minted | **Recommended.** DCQL `type_values: ["GovernancePolicyCredential"]` plus a `domain` claim constraint; the gateway is a pre-trusted verifier in its own domain, so the auto-consent path answers immediately. Zero new tasks; the VTA already carries holder-side machinery (`vta-service/src/operations/credential_exchange.rs`). |
| New `vta/credentials/list`/`show` read pair | A defensible future addition (the family currently has no read side), but not needed for #804 — and the constraint says don't add it until something needs it. |
| `policy/active` returning/pointing at the credential | Wrong family (Rego bindings, `PolicyAdmin` gate the gateway must not hold) and not bound on the VTA anyway. |

One honest wrinkle: holder-of-record here is the VTA itself presenting credentials it issued about a domain, rather than the subject presenting credentials about itself. Nothing in `credential-exchange/query`'s contract forbids it — the no-enumeration and consent rules apply unchanged — but it is called out in the registry PR's reviewer checklist as a deliberate semantics question.

## The trust argument — why this chain actually closes #804

A verifier holding an attestation that cites `policyHash` now checks:

1. the attestation's signature (unchanged — the witness property, out of scope here);
2. the cited policy credential: issuer is the domain's VTA DID, `credentialSubject.domain` matches the domain the attestation speaks for, `policyHash` matches, validity window open;
3. the credential's `credentialStatus` bit is clear on the published status list.

Every element of (2) and (3) is verifiable without trusting the gateway host. The policy referent has moved from a host-editable file to a VTA-signed artifact whose rotation requires operator step-up. A compromised host can still *disobey* the policy (the #817 residual), but it can no longer *define* it — and because the profile obliges the enforcing component to load its runtime policy from the verified credential and **fail closed** when none is obtainable, the two Cierge gaps #804 names (fail-closed-by-validation allowlist, operator-dependent privacy-tier cross-check) become structural rather than configured. Citation-without-consumption is explicitly non-conforming: with V1 declined there is no issuance-side check that cited policy matches enforced policy, so consumption discipline is where that gap is held.

## Revocation semantics, precisely

- **Rotation is supersession, not revoke-then-issue.** One `vta/credentials/issue` call revokes the predecessor atomically and reports it as `supersedes`. There is no window where zero or two policies are live, and no half-completed operator sequence.
- **`vta/credentials/revoke` is the emergency path** — the policy is wrong and no successor exists yet. Afterwards no active policy credential exists for the domain and a conforming gateway refuses that domain's traffic. Reverting to local file config would resurrect exactly the artifact this design retires.
- **Status-list slots are never reclaimed** (cached-list un-revocation hazard, same rule as VTC).
- **Expiry is the backstop.** `validitySeconds` bounded to hours-to-days limits how long a stale cached status list keeps a superseded policy citable; re-issuance on a cadence is cheap because rotation is one call.

## Implementation sketch *(deferred — nothing below is in this PR)*

| Piece | Where | Shape |
|---|---|---|
| Profile validation, hash recomputation, single-active supersession | `vta-service/src/operations/credentials.rs`, `vta-service/src/trust_tasks/credentials.rs` | Branch on `credential_type == "GovernancePolicyCredential"`; index live profile credentials by `(context_id, domain)`; revoke displaced record in the same transaction; return `supersedes`. |
| Status-list **producer** on the VTA | new `vta-service/src/status_list/` (port the allocator/publisher pattern from `vtc-service/src/status_list/`), new keyspace in `vta-keyspaces` | `affinidi-status-list 0.1.3` is already a workspace dependency; `vta-vault/src/status.rs:21` already flags the `status_lists` keyspace as the planned follow-up. Publish unauthenticated `GET /v1/status-lists/{purpose}`, Trust-Task-exempt like VTC's route. |
| `credentialStatus` stamping at mint | `vta-service/src/operations/credentials.rs` | Allocate slot before returning the credential (VTC's durability rule). |
| Wire types | `vta-sdk/src/protocols/credentials_issuance.rs` | `Option<String> supersedes`, `Option<u64> status_list_index` — additive, serde-skippable; no URI changes, so no `wire_v0_2.rs` dual-accept work at all. |
| Holder-side discoverability | `vta-service/src/operations/credential_exchange.rs` | Register minted profile credentials in the DCQL type index so `credential-exchange/query` finds them. |
| Consumption | Cierge side — affinidi/cierge#44 (fetch/load), affinidi/cierge#46 (consume correctly) | Out of scope for this repo. |

`vta-policy`, the PDP, is deliberately untouched: governance-parameter credentials and Rego decision policies stay different layers (`ContextPolicy` in `vta-sdk/src/context_policy.rs` likewise remains the VTA's own quota primitive, not this credential's payload).

## What this note does *not* argue

- That attestation becomes proof of compliance — the request-path witness can still lie (#804's own honest scope, #817's territory).
- That the `policy/*` registry family is deficient — it models decision policies well; it is simply the wrong carrier for enforcement parameters.
- That a `vta/credentials` read pair should never exist — only that #804 does not need it.

## Summary

| #804 ask | Carried by | New tasks |
|---|---|---|
| Issuance | `vta/credentials/issue/0.2` + `GovernancePolicyCredential` claims profile | 0 |
| Revocation | `vta/credentials/revoke/0.1` + published status list (endorsements mechanic) | 0 |
| Distribution | `credential-exchange/query` → `present` | 0 |

Related: [`multi-tenant-signing.md`](multi-tenant-signing.md), [`acl-scope-semantics.md`](acl-scope-semantics.md), [`vti-credential-architecture.md`](vti-credential-architecture.md), [`vtc-trust-task-registry-migration.md`](vtc-trust-task-registry-migration.md).
