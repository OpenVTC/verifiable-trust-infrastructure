# Publishing the last 67 Trust Tasks — reduce first, then author

**Status:** proposal. No code changes yet.
**Context:** the widened census in #821 (`every_bound_canonical_task_exists_in_the_registry`)
found 67 bound URIs claiming the `trusttasks.org/spec/` authority that the
registry does not publish. They are held by counted family exceptions in
`vtc-service/tests/trust_task_manifest.rs`, which stops the debt growing but
does not shrink it.

---

## The goal, stated precisely

Not "publish 67 specs". The goal is **the fewest interfaces that cover the
surface, each reusable over REST, DIDComm and TSP**. A Trust Task is a
contract; publishing 67 of them when 30 would do is 37 contracts to maintain,
version and keep consistent forever.

So the order is: **fold what already exists, generalise what nearly exists,
author only what genuinely doesn't.**

One thing to be clear about up front, because it changes the urgency: **these
are already Trust Tasks and already dispatch over DIDComm and TSP.**
`vta-service/src/trust_tasks/mod.rs` routes every one of them today. What is
missing is *publication* — the specs are unresolvable, so a third party cannot
build against them and no consumer can validate a payload it receives. This is
an interoperability and governance gap, not a transport gap.

## The trap this analysis must avoid

Recorded from #710, where it cost real time: **names and one-line summaries are
not evidence of duplication.** `policies/upload` "obviously" matched
`policy/upsert` and did not. Every fold below is either payload-diffed or
explicitly marked as needing one. A fold asserted from a slug is not a finding.

The converse trap is new here and just as expensive: **two tasks with the same
name on different sides of a wire are not necessarily duplicates — but they are
not necessarily distinct either.** See `webvh` below.

---

## Disposition

### A. Folds onto already-published canonical tasks — 9 tasks, 0 new specs

The registry already publishes a generic equivalent. VTC performed exactly
these folds during #710 (phases 2c and 2d), so there is a worked example
including the payload reconciliation.

| Bound today | Folds onto | Confidence |
|---|---|---|
| `vta/acl/create/1.0` | `acl/grant/0.1` | payload-diffed |
| `vta/acl/get/1.0` | `acl/show/0.1` | payload-diffed |
| `vta/acl/list/1.0` | `acl/list/0.1` | payload-diffed |
| `vta/acl/update/1.0` | `acl/change-role/0.1` | payload-diffed |
| `vta/acl/delete/1.0` | `acl/revoke/0.1` | payload-diffed |
| `vta/config/get/1.0` | `config/show/0.1` | VTC precedent |
| `vta/config/update/1.0` | `config/patch/0.1` | VTC precedent |
| `vta/audit/list-logs/1.0` | `audit/list/0.1` | VTC precedent |
| `vta/provision-integration/request/1.0` | `provision/integration/0.2` | needs payload diff |

**The ACL fold is closer than expected.** Canonical `AclEntry` already carries
`subject`, `role`, `label`, `scopes`, `stepUp`, `expiresAt`, `createdAt/By`,
`updatedAt/By` and `ext`. Mapping from `CreateAclBody` is:

- `did` → `subject`
- `allowedContexts` → `scopes`
- `expiresAt` u64 epoch → RFC 3339 `date-time`
- `stepUpApprover` / `stepUpRequire` → the existing `stepUp` member (**verify
  its shape covers both**)
- flat body → nested under `entry`

Only one thing has no canonical home: **`approveAllContexts` / `approveContexts`**,
the approve-vs-act authority axis (`vta-sdk/src/acl.rs`, `ApproveScope`). That
is a real modelling gap in canonical `AclEntry`, not a VTA quirk — "may confer
access but not exercise it" is a generic delegation concept. Proposal: extend
canonical `AclEntry` with an `approveScopes` member rather than hiding it in
`ext`, since a consumer that ignores it grants *less* than intended, which is
the safe direction, whereas a consumer that misreads it grants more.

### B. Two ends of one wire — `vta/webvh/*` (17), needs a decision

This is the largest group and the one most likely to be got wrong.

`did-management/*` (29 published) is the **hosting server's** API — what a
did-hosting service implements. `vta/webvh/*` is the **client's** — what a VTA
does to manage the hosts it knows, the DIDs it owns, and names on them. The VTA
*calls* did-management.

They are therefore not duplicates. But for several verbs the payload is the
same object crossing two hops:

```
operator → VTA : "set agent name X on DID D"
VTA → host     : "set agent name X on DID D"     ← did-management/agent-name/set/0.1
```

If those payloads match, the right answer is **one task dispatched twice**, not
two tasks — which is the strongest available form of the reuse we want.

| Bound today | Candidate | Needs |
|---|---|---|
| `vta/webvh/agent-name/{set,remove,disable,enable}/1.0` (4) | `did-management/agent-name/{set,remove,disable,enable}/0.1` | payload diff — likely direct reuse |
| `vta/webvh/agent-name/check/1.0` | `did-management/did/check-name/0.1` | payload diff |
| `vta/webvh/dids/{delete,list,get}/1.0` (3) | `did-management/did/{delete,list,info}/0.1` | payload diff |
| `vta/webvh/dids/{create,get-log,rotate-keys,register-with-server}/1.0` (4) | — | likely genuinely VTA-side |
| `vta/webvh/agent-name/list/1.0` | — | no canonical counterpart |
| `vta/webvh/servers/{add,list,update,remove}/1.0` (4) | — | the VTA's own registry of known hosts; `did-management/server/register` is the *host* registering itself, a different subject |

Optimistic outcome 17 → 9 new; pessimistic 17 → 13.

### C. Generalise, don't duplicate — the vault lifecycle (12)

`vault/{archive,unarchive,restore,purge}/0.1` (4) and
`vault/credentials/{archive,unarchive,restore,purge,get,query,receive,delete}/0.1` (8)
are two parallel surfaces over two stores — the password vault and the
credential store. The lifecycle verbs are *identical in meaning*; only the store
differs.

Publishing twelve tasks would enshrine that duplication in the registry. The
reuse-first answer is a **store discriminator**:

- Author `vault/{archive,unarchive,restore,purge}` **once**, taking the store
  as a payload member.
- Fold `vault/credentials/{get,query,receive,delete}` onto the published
  `vault/{get,list,upsert,delete}` with the same discriminator.

**12 → 4 new.** The cost is a new version of the published `vault/*` tasks
(0.2 → 0.3) to add the discriminator, and a decision on its default — which
must be the password vault, so an existing caller that omits it keeps its
current meaning.

**Open question worth answering before building:** is a credential genuinely the
same *kind* of thing as a vault secret, or does the shared lifecycle hide two
different authorization models? #540 gave the credential store its own
capability (`CredentialWrite`) precisely because removing someone's credentials
is higher-trust than removing a password. A single task with a store selector
must not let a `VaultWrite` holder reach the credential store by flipping a
field.

### D. New canonical generic families — 13 tasks

No canonical equivalent, but nothing VTA-specific about them either. These
should be authored **top-level**, not under `vta/`, so other agents can use them
— and so the existing `vtc/backup/*` can fold onto the backup family later.

| Bound today | Author as | Note |
|---|---|---|
| `vta/keys/{create,get,list,rename,revoke,sign,derive-and-sign,derive-and-sign-document}/1.0` (8) | `keys/*` | The signing-oracle surface. Generic to any agent holding keys. |
| `vta/backup/{initiate-export,complete-export,initiate-import,finalize-import,abort}/1.0` (5) | `backup/*` | Two-phase descriptor flow. Richer than `vtc/backup/{export,import}`, which should fold onto it rather than the reverse. |

### E. Genuinely VTA-specific — publish under `vta/` (16)

| Bound today | Count | Why it stays `vta/` |
|---|---:|---|
| `vta/contexts/*` | 7 | The BIP-32 key-hierarchy context tree. Tied to the VTA's derivation model. |
| `vta/seeds/*` | 3 | Master-seed lifecycle. Meaningless to an agent that is not the key authority. |
| `vta/attestation/*` | 2 | Nitro/SEV attestation posture. |
| `vta/audit/{get,update}-retention` | 2 | Extends the canonical `audit/*` family; author as `audit/retention/{show,update}` if generic, else `vta/`. |
| `vta/discovery/capabilities` | 1 | Overlaps `trust-task-discovery/*` — **needs a diff**. |
| `vta/management/reload-services` | 1 | Overlaps `config/reload` — **needs a diff**. |

### F. Not a task — 1

`trust-task-error/0.1` is the framework's error **envelope**, a response type
deliberately absent from the task index. Permanent exception, no work.

---

## Net effect

| | Tasks |
|---|---:|
| Bound and unpublished today | 67 |
| Eliminated by folding onto published tasks (A) | −9 |
| Best case from the webvh decision (B) | −8 |
| Eliminated by the vault store discriminator (C) | −8 |
| **Estimated published outcome** | **~42** |

Plus two existing canonical families extended (`acl` gains `approveScopes`,
`vault` gains a store discriminator), and `vtc/backup/*` folding onto the new
`backup/*` later — a further reduction outside this count.

## Suggested sequencing

Ordered by (confidence × value) ÷ blast radius:

1. **A — the nine folds.** Highest confidence, zero new specs, and it deletes
   VTA wire surface rather than adding any. Note this *is* a breaking change to
   the VTA's ACL and config payloads; VTC's #710 phases 2c/2d are the template.
2. **D — `keys/*` and `backup/*`.** Purely additive: author upstream, repoint,
   nothing else moves. Good second step because it needs no cross-family
   decisions.
3. **E — the VTA-specific 16.** Mechanical once D establishes the authoring
   rhythm. Resolve the two "needs a diff" rows first.
4. **C — the vault generalisation.** Needs the authorization question answered
   before any spec is written.
5. **B — webvh.** Largest and least understood; do it once the others have
   settled the conventions.

Each phase is a registry PR followed by a VTI PR, as #147/#834 and #148/#837
were. The counted exceptions in `trust_task_manifest.rs` come down with each
phase, which is the progress metric.
