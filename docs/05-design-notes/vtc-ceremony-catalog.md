# VTC Ceremony Catalog — Instances of the Pipeline

**Status:** Design proposal (for review) · **Parent:** [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md)
**Purpose:** Prove the one pipeline generalizes by running maximally-different ceremonies through it,
then map the remaining purposes. If the abstraction only ever served admission, it would be
over-engineering. The four matrix rows below exercise it along every axis that matters; admission
itself is then instantiated four ways (§2.1–§2.4) for different stages of community maturity.

> **Notation.** Bare `§N` references are to [`vtc-ceremony-pipeline.md`](./vtc-ceremony-pipeline.md). MVP
> references are written `vtc-mvp.md §N`.

---

## 1. The validation matrix

The active ceremony family is four community-lifecycle admission phases plus three member-lifecycle
ceremonies, chosen to differ on *every* axis — if one pipeline handles all four matrix rows, it handles
the rest.

| Ceremony | Trigger / `actor` | `actor` = `subject`? | Evidence | Effects | Hard invariant | Threaded? | Direction |
|---|---|---|---|---|---|---|---|
| **Admission** (Phase 1–4) | applicant (unauth) | **yes** | VP (invitation + relationship + identity credentials) | issue VMC + VEC, write ACL+Member | privilege ceiling | yes | constructive |
| **Leave** | member (self) **or** admin | **no** (admin case) | disposition choice / removal reason | revoke VMC, apply disposition, registry departure | no-last-admin | optional | **destructive** |
| **Role-change** | admin | **no** | target + desired role (+ step-up) | re-issue VEC, update ACL role | privilege ceiling + step-up | optional | **mutating** |
| **Directory** | any member (a query) | **no** | the query (fields requested) | return a **field projection** (no write) | PII boundary | **no** (sync) | **read-only** |

Admission is constructive/self/threaded (instantiated four ways for different stages of community maturity
— §2); Leave inverts it (destructive/other/one-shot); Role-change is in-place mutation with an escalation
guard; Directory is a stateless read that returns a *filter*, not a boolean. All four matrix rows are the
**same** `verify → facts → evaluate → verdict → effects` pipeline with different plug-ins.

---

## 2. Admission — four phases of community growth

The canonical matrix row from §1, instantiated four ways. Per the *VTC Bootstrapping* spec, a community
progresses through four phases as its web of trust matures: the **initiator** self-bootstraps, then
invites **community trust anchors**, who then invite **members**, who can themselves invite new members
(with identity verification). Each phase is the same pipeline shape — applicant is both actor and
subject; allow issues a VMC + role VEC + reciprocal edge — but each requires a different credential
bundle and grants a different role.

The privilege ceiling applies to every phase: no admission route grants `admin`. (Phase 1 grants
`initiator`, which is distinct from `admin` and only ever applies at genesis.)

### 2.1 Phase 1 — Initiation (genesis)

- **Trigger:** the initiator, before the community exists. The PNM runs this client-side; the VTA
  doesn't exist yet to evaluate the IR.
- **Evidence:** none — no presentation, no invitation.
- **Routes (`phase1.rego`):** `actor_is_initiator → allow(role: initiator)`; else `deny`.
- **Verdict realization (out of band):** PNM generates a community DID (C-DID), instantiates the VTA via
  a trust task with a DTG service provider, has the VTA mint the initiator's VMC, and writes
  `{member: initiator M-DID, role: initiator}` to the trust registry.
- **Invariant:** privilege ceiling holds vacuously (no `admin` grant possible).

The IR is degenerate but kept for design completeness and the visual guide — it surfaces the
layered-trust progression that begins at "initiator".

### 2.2 Phase 2 — Initiator invites community trust anchors

- **Trigger:** an invitee who holds a **VTC invitation credential (VIC)** issued by the initiator.
- **Evidence:** `invitation: { verified, consumed, issuer, issuer_role, scopes }`.
- **Routes (`phase2.rego`):** `has_valid_invitation AND invitation_issuer_has_role("initiator") →
  allow(role: trustAnchor)`; else `request_more(needs: ["invitation:from-initiator"])`.
- **Verdict realization:** `allow` ⇒ VTA issues VMC + role VEC for `trustAnchor`, writes
  `{member: CTA M-DID, role: trustAnchor}` to the registry; `request_more` ⇒ PD asking for an
  initiator-issued VIC.
- **Effects (allow):** allocate status-list index → mint VMC + role VEC → write ACL + Member →
  sealed-transfer → audit. Obligation `reciprocate_vmc`.
- **Invariant:** privilege ceiling (no admin); plus the PEP may also enforce a community-policy limit
  on how many CTAs may be admitted (out of scope for the IR).

### 2.3 Phase 3 — Community trust anchors invite members

- **Trigger:** an invitee with a VIC from a CTA **and** a verifiable relationship credential (VRC) from
  a *different* CTA. The cross-anchor VRC means admission is independently witnessed.
- **Evidence:** `invitation` (issued by a CTA) + `presentation.credentials` containing at least one
  trusted VRC whose `issuer_role_in_community == "trustAnchor"` and whose issuer ≠ the VIC issuer.
- **Routes (`phase3.rego`):** `has_valid_invitation AND invitation_issuer_has_role("trustAnchor") AND
  holds_credential_from_role({type:"VerifiableRelationshipCredential", role:"trustAnchor",
  exclude_invitation_issuer:true, min:1}) → allow(role: member)`; else
  `request_more(needs: ["invitation:from-trustAnchor", "vrc:from-different-trustAnchor"])`.
- **Verdict realization:** `allow` ⇒ VTA issues VMC + role VEC for `member`, writes
  `{member: invitee M-DID, role: member}`. `request_more` ⇒ PD listing the missing artifacts.
- **Effects (allow):** as Phase 2, with `role: member`.
- **Invariant:** privilege ceiling; plus the `exclude_invitation_issuer` flag is what enforces the
  "different CTA" semantic — a CTA can't both invite and self-vouch.

**Worked example (1 VIC + 1 VRC from same CTA → request_more):**

```jsonc
{ "purpose":"phase3", "now":"…",
  "actor":   { "did":"did:key:z6MkInvitee", "authenticated":false },
  "subject": { "did":"did:key:z6MkInvitee" },
  "context": { "community_did":"did:webvh:acme.example", "channel":"rest", "member_count":7 },
  "evidence":{
    "invitation":{ "verified":true, "consumed":false,
      "issuer":"did:key:z6MkAnchorA", "issuer_role":"trustAnchor", "scopes":["membership"] },
    "presentation":{ "verified":true, "holder":"did:key:z6MkInvitee",
      "credentials":[
        { "type":"VerifiableRelationshipCredential", "issuer":"did:key:z6MkAnchorA",
          "issuer_trusted":true, "issuer_role_in_community":"trustAnchor", "status":"valid",
          "claims":{"kind":"knows"} } ] } },
  "state":{ "subject_member":null } }
```

The VRC's issuer equals the VIC issuer (z6MkAnchorA) → `credential_distinct_issuer_count_excl_inviter`
yields 0 → first route fails → `request_more(needs: ["invitation:from-trustAnchor",
"vrc:from-different-trustAnchor"])`. Swap the VRC's issuer to `z6MkAnchorB` (a different CTA) → the
first route matches → `allow(role: member)`.

### 2.4 Phase 4 — Members invite other members

- **Trigger:** an invitee with a VIC from a member, **two** VRCs from two **other** distinct members
  (excluding the inviter), **and** an identity verification credential (IDVC) from an approved IDVP.
- **Evidence:** `invitation` (member-issued) + `presentation.credentials` with (a) at least two trusted
  VRCs from distinct members, none equal to the inviter, and (b) one IDVC whose
  `issuer_role_in_community == "identityVerificationProvider"`.
- **Routes (`phase4.rego`):** four-clause `all`: `has_valid_invitation` + `invitation_issuer_has_role
  ("member")` + `holds_credential_from_role({type:"VerifiableRelationshipCredential", role:"member",
  exclude_invitation_issuer:true, distinct_issuers:true, min:2})` + `holds_credential_from_role
  ({type:"IdentityVerificationCredential", role:"identityVerificationProvider", min:1})` →
  `allow(role: member)`; else `request_more(needs: ["invitation:from-member",
  "vrc:from-other-members:distinct>=2", "idvc:from-approved-idvp"])`.
- **Verdict realization:** `allow` ⇒ VTA issues VMC + role VEC for `member`. The IDVP's role must be
  registered as `identityVerificationProvider` in the community trust registry — that's a precondition
  for `issuer_role_in_community` to populate correctly during Verify, not a Rego check.
- **Effects (allow):** as Phase 2/3.
- **Invariant:** privilege ceiling; the cross-issuer constraints (≠ inviter, distinct issuers) live in
  the `holds_credential_from_role` helper's set comprehension, not in Rego boilerplate.

---

## 3. Leave / Exit (offboarding) — *the inverse of admission*

Chosen to invert admission. Maps to MVP `removal` (`vtc-mvp.md` §10.2).

- **Trigger:** the **member** (voluntary self-exit) **or** an **admin** (involuntary removal). So `actor` may be
  the subject or a third party — the pipeline carries both in `actor`/`subject`.
- **Evidence:**
  - self → a `request: { disposition: Purge | Tombstone | Historical | PolicyDefault }` (`vtc-mvp.md` §10.2).
  - admin → a `request: { reason }` + the target as `subject`.
- **Routes (policy `leave.rego`):** e.g. `actor_is_self → allow(disposition from request | policy default)`;
  `actor_is_admin AND not subject_is_admin → allow(disposition default)`;
  `actor_is_admin AND subject_is_admin → refer(second-admin)`; else `deny`.
- **Verdict realization:** `allow.with.disposition` carries the departure disposition (the policy *decides* it,
  generalizing admission's `role`). `refer` ⇒ a second admin must co-sign. `request_more` ⇒ e.g. require a
  documented-reason credential. `deny` ⇒ refuse (policy protects certain roles).
- **Effects (allow):** revoke VMC (flip status-list bit, immediate) → delete/anonymize the Member record per
  disposition → enqueue registry departure → audit `MemberRemoved`. **Destructive — issues nothing.**
- **Invariant:** **no-last-admin** — host refuses any leave/removal that would zero the admin set
  (`vtc-mvp.md` §10.2), regardless of policy.

**What this proves:** `actor ≠ subject`, destructive effects, a *different* hard invariant, and that the
`allow` payload is purpose-shaped (`disposition`, not `role`) — all on the same pipeline, with the same verify
stage and the same four verdicts.

**Worked example (admin removing a member):**

```jsonc
{ "purpose":"leave", "now":"…",
  "actor":   { "did":"did:key:z6MkAdmin", "role":"admin", "authenticated":true },
  "subject": { "did":"did:key:z6MkLeaver" },
  "context": { "community_did":"did:webvh:acme.example", "channel":"rest", "member_count":1421 },
  "evidence":{ "request":{ "reason":"code-of-conduct-violation" } },
  "state":   { "subject_member":{ "role":"member", "status":"active", "joined_at":"…" } } }
```

`actor_is_admin AND not subject_is_admin` → `{"effect":"allow","with":{"disposition":"Tombstone"}}`. Host runs
the destructive effects; the no-last-admin guard is moot here (subject isn't an admin) but would have refused
had `subject.role == "admin"` and the set would empty.

---

## 4. Role-change / promotion — *in-place mutation + escalation*

- **Trigger:** admin. `actor ≠ subject`.
- **Evidence:** `request: { target_role }`; for promotion-to-admin, a fresh **step-up** user-verification.
- **Routes (`role-change.rego`):** `target_role in {member,moderator,custom:*} → allow(target_role)`;
  `target_role == "admin" → refer(step-up)` *(or quorum)*; demotion guarded by no-last-admin.
- **Verdict realization:** `allow.with.role` ⇒ re-issue the role VEC + update the ACL role (mutation, not
  issuance-from-scratch). `refer` ⇒ the step-up / M-of-N path.
- **Effects (allow):** re-issue role VEC → update ACL role → audit `RoleChanged`. No new membership.
- **Invariants:** privilege ceiling (policy can't grant admin directly) **and** step-up reauth for admin
  promotion (`vtc-mvp.md` §9.7, §10.4) **and** no-last-admin on demotion.

**What this proves:** the pipeline handles *mutation of an existing member*, and that `refer` cleanly models an
**escalation** (step-up / quorum), not just human moderation. Two invariants stack on one ceremony.

---

## 5. Directory access — *read-time, synchronous, returns a filter (the stress test)*

Deliberately included because it's the ceremony most likely to break a naïve "verdict + effects + thread" model.

- **Trigger:** any member issues a query. `actor` = viewer, `subject` = the member being looked up.
- **Evidence:** `request: { fields_requested }`.
- **Routes (`directory.rego`):** `allow(fields: <subset visible to actor.role>)` — the policy returns a **field
  projection**, not a yes/no. e.g. members see `{did, role}`; admins see more.
- **Verdict realization:** `allow.with.fields` is the *permitted projection*. `deny` ⇒ empty result.
  `refer`/`request_more` are unused.
- **Effects (allow):** **return the projection in the same response — no state write, no thread.**
- **Invariant:** PII boundary (`vtc-mvp.md` §8.1) — fields outside the projection never leave.

**What this proves — the important one:** the pipeline **degrades to a stateless, synchronous read filter**.
There is no thread, no issuance, no mutation; `allow` carries a *projection* rather than an obligation. If one
abstraction spans a multi-day admission negotiation (phase 4) *and* a sub-millisecond field filter (directory)
without special-casing, the pipeline is the right shape — and threads/effects are correctly modelled as
*optional, purpose-specific* rather than mandatory.

---

## 6. Capability escalation — exemplars

§4's `role-change` is the generic in-place mutation primitive. In real OSS communities, capability
escalation has shape that the generic ceremony abstracts over: who can sponsor whom, whether one
signature suffices or a quorum is required, whether the granted role carries a path scope, whether
there's a structural prerequisite. The two exemplars below — modeled on the Linux kernel and Kubernetes
— exercise opposite points in that design space using **the same IR vocabulary** plus one small leaf
(`invitation_has_scope`).

Both ceremonies are *applications* of the role-change shape, not replacements. They illustrate how a
community would express its specific promotion rules; the generic `role-change` (§4) remains the
default for communities without specialized needs. Both grant non-admin roles, so the privilege ceiling
(`vtc-ceremony-rule-ir.md` §4) holds.

### 6.1 Linux LKMV — subsystem maintainer addition

- **Trigger:** a candidate developer who has been sustaining maintenance work in some part of the tree.
  A super-maintainer (or Linus) authors a patch adding their name to the `MAINTAINERS` file, encoded
  here as a VTC invitation credential.
- **Evidence:** `invitation: { verified, consumed, issuer, issuer_role: "super-maintainer", scope:
  "<path-glob>" }`. The `scope` field is the path the new maintainer's authority covers.
- **Routes (`lkmv-maintainer.rego`):** `has_valid_invitation AND invitation_issuer_has_role
  ("super-maintainer") AND invitation_has_scope → allow(role: maintainer)`; else
  `request_more(needs: ["invitation:from-super-maintainer", "invitation:scope-required"])`.
- **Verdict realization:** `allow` ⇒ VTA issues role VEC scoped to `evidence.invitation.scope`, writes
  ACL entry recording the path-scoped grant.
- **Effects (allow):** issue role VEC → write ACL + Member-as-maintainer record (carrying the scope) →
  sealed-transfer → audit. Obligation `accept-maintainership`.
- **Invariant:** privilege ceiling (no admin); plus an implicit *single-sponsor sufficiency* — Linux
  governance encodes its informality by *not* gating on a quorum.

**What this exemplar proves about the IR:** path-scoped roles fit cleanly via an optional invitation
field (`pipeline.md` §3). The Linux *style* — informal, single-signer — turns out to need essentially
no vocabulary beyond what Phase 2 already provides. The policy is two routes, one new leaf, one new
helper.

### 6.2 Kubernetes Approver — Reviewer → Approver promotion

- **Trigger:** a candidate already holding role `reviewer` (per the trust registry) who has accumulated
  sponsorship from existing approvers. Each sponsoring approver issues a `PromotionEndorsementCredential`
  to the candidate.
- **Evidence:** `presentation.credentials[]` containing ≥2 `PromotionEndorsementCredential`s whose
  issuers each hold `issuer_role_in_community == "approver"`.
- **Routes (`k8s-approver.rego`):** three routes, in priority order:
  1. `subject_has_role("reviewer") AND holds_credential_from_role({type:"PromotionEndorsementCredential",
     role:"approver", distinct_issuers:true, min:2}) → allow(role: approver)`.
  2. `subject_has_role("reviewer") → request_more(needs: ["endorsement:from-approver:distinct>=2"])`.
  3. `always → deny(code: "k8s-approver-requires-reviewer-first")`.
- **Verdict realization:** `allow` ⇒ VTA re-issues role VEC as `approver`, updates ACL. `request_more`
  ⇒ PD asking for more endorsements. `deny` ⇒ tells the caller they must be a reviewer first.
- **Effects (allow):** re-issue role VEC → update ACL role → audit. Obligation
  `accept-approver-duties`.
- **Invariant:** privilege ceiling; plus a *structural prerequisite* — promotion to approver requires a
  prior reviewer role (recorded in the trust registry).

**What this exemplar proves about the IR:** M-of-N is *not a new primitive* — it's
`holds_credential_from_role` applied to a credential type named `PromotionEndorsementCredential`. The
same set-comprehension cardinality that drove Phase 3 (VRC from a different CTA) and Phase 4 (≥2 member
VRCs) drives Kubernetes-style quorum-based promotion. The three-route policy demonstrates `allow /
request_more / structural-deny` in one ceremony.

### Why both — and what they show together

Each exemplar exercises a different point on two axes from `vtc-ceremony-rule-ir.md`:

| Axis | Linux (LKMV) | Kubernetes (Approver) |
|---|---|---|
| Sponsorship | M-of-1 (single super-maintainer) | M-of-N (≥2 distinct approvers) |
| Promotion criteria | Sponsor's judgment, no thresholds | Endorser credentials + structural prerequisite |
| Scope | Path-glob on the invitation | Project-wide (informational scope on endorsements only) |

The IR vocabulary that expresses Kubernetes is a strict superset of what's needed for Linux — and that
superset is small (the `holds_credential_from_role` leaf, already used by admission). One vocabulary
covers both governance philosophies expressively, which is the design point.

---

## 7. Per-action attestation — issuance ceremonies

The matrix row in §1 describes four ceremony *shapes*: constructive (admission), destructive (leave),
mutating (role-change), read-only (directory). The two exemplars in this section introduce a **fifth
shape — issuance of fresh per-action credentials**. The verdict's `allow` doesn't grant a role, change
a role, or return a projection; it signals to the host that a new credential should be minted, bound
to the actor's M-DID and the action's data (commit SHA, branch, parents, reviews, etc.).

Per-action attestation is the OSS-distinctive ceremony category. In a generic community, the actions
are mostly meta (joining, leaving, voting). In open source the *product itself* is a stream of
artifacts — commits, reviews, merges, releases — and the integrity of the software depends on the
integrity of these per-action micro-ceremonies. Sigstore, SLSA, in-toto already provide the
cryptographic substrate; VTC's contribution is **binding the signing keys to community roles at the
moment of signing**, so downstream verifiers can check both "did this key sign?" and "was the key
authorized as role R at time T?".

The two exemplars below mirror the same Linux/Kubernetes spectrum we saw in §6, applied to the merge
event:

### 7.1 LKMV merge — Linux subsystem maintainer merge attestation

- **Trigger:** a Linux maintainer records that they merged a patch series into their tree.
- **Evidence:** `request: { commit_sha, parent_shas, branch, signoff_chain }`. The actor is the
  merging maintainer, authenticated via their M-DID.
- **Routes (`lkmv-merge.rego`):** one-clause gate — `actor_has_role("maintainer") → allow(issues_attestation:
  "MergeAttestation")`; else `deny(code: "lkmv-merge-requires-maintainer-role")`.
- **Verdict realization:** `allow` ⇒ host mints a `MergeAttestation` VC binding `actor.did` +
  `actor.role` + `now` to the request's commit data. The host's responsibility includes packing the
  signoff chain, scope (if known from MAINTAINERS), and any in-toto layer-attestation references
  into the credential's claims.
- **Effects (allow):** mint MergeAttestation → publish to chain → audit. Obligation
  `chain-to-parents` (the new credential references the parent commits' attestations, if any).
- **Invariant:** per-action attestation purposes must not also grant a role (§4 invariants).

**What this exemplar proves:** the IR can express *issuance ceremonies* with a tiny vocabulary
delta — a one-clause gate plus the new `issues_attestation` allow payload. The complexity of the
resulting credential's structure (which commits, which signoff trail, which scope) lives in the
host's effect handler, not in the policy. The policy answers *whether* to issue, not *what*.

### 7.2 K8s Prow merge — Kubernetes Prow bot merge attestation

- **Trigger:** Kubernetes Prow's Tide bot records a PR merge after the PR satisfied review criteria.
- **Evidence:** `request: { commit_sha, parent_shas, branch, pr_number }` + `presentation.credentials`
  containing the underlying `ReviewAttestation`s (at least one `approve` from an Approver and one
  `lgtm` from a Reviewer). Actor is Prow itself, holding role `merge-bot` via a forward-looking
  `AutomationMembershipCredential`.
- **Routes (`k8s-prow-merge.rego`):** five routes, in priority order:
  1. bot + approve + lgtm → `allow(issues_attestation: "MergeAttestation")`.
  2. bot + lgtm-only → `request_more(needs: ["review:approve-from-approver"])`.
  3. bot + approve-only → `request_more(needs: ["review:lgtm-from-reviewer"])`.
  4. bot + nothing → `request_more(needs: [both])`.
  5. not-the-bot → `deny`.
- **Verdict realization:** `allow` ⇒ host mints a `MergeAttestation` that *chains to* the underlying
  ReviewAttestations (the obligation `chain-to-reviews` records this). The provenance trail becomes:
  `MergeAttestation → references → ReviewAttestation[] → references → commit SHA`. A downstream
  verifier can walk the chain end-to-end.
- **Effects (allow):** mint MergeAttestation + chain references → publish → audit. Obligations
  `chain-to-reviews` + `chain-to-parents`.
- **Invariant:** same as 7.1 (per-action attestation purposes must not grant a role).

**What this exemplar proves:** the IR can express *graceful degradation* across five routes — each
missing piece of evidence gets a distinct `request_more` verdict with the specific `needs` list. The
M-of-N gate (≥1 approve + ≥1 lgtm) reuses the existing `holds_credential_from_role` primitive applied
to a new credential type (`ReviewAttestation`). The bot-as-actor pattern requires a forward-looking
`AutomationMembershipCredential` (`vtc-ceremony-pipeline.md` §3.4 sketch).

### 7.3 Why both — and what's next

The two exemplars together establish:

- **Per-action attestation is the fifth ceremony shape** (alongside the four §1 matrix rows). Same
  pipeline, same evidence-collection mechanics, same threading machinery — just a different
  `allow.with` payload.
- **Issuance reuses M-of-N primitives**: `holds_credential_from_role` over `ReviewAttestation` credentials
  is the same primitive that drives Phase 3/4 admission and K8s Approver promotion. The
  set-comprehension cardinality pattern generalizes across the catalog.
- **Bot-as-actor is essential** for K8s-style automation. The `AutomationMembershipCredential` sketch
  in pipeline.md §3.4 names the gap; building the full bot-onboarding ceremony is future work.
- **Temporal verification** is a real downstream concern. The IR is point-in-time; the trust registry
  must answer "what role did this DID hold at time T?" for retrospective audits to work. The API
  contract is sketched in pipeline.md §3.5; the implementation is future work.

The two ceremonies together cover the spectrum from minimal (Linux one-clause) to richly composite
(Kubernetes bot + multi-credential + chain-references). Both fit in the existing IR vocabulary with
exactly one new shared leaf (`actor_has_role`) and one new `allow.with` payload key
(`issues_attestation`).

---

## 8. The remaining purposes map cleanly

The other `vtc-mvp.md` §7.1 purposes are further instances — listed to show coverage, not specified here:

| Purpose | `actor` / `subject` | Evidence | `allow` effect | Notes |
|---|---|---|---|---|
| **Personhood** | member self | VP w/ `WitnessCredential` | set `personhood` flag, re-mint VMC | minimal-allow default (`vtc-mvp.md` §6.4) |
| **Relationship** (VRC) | member → other member | self-issued VRC | store edge if both are members | `vtc-mvp.md` §12.3 |
| **Renewal** | member self | none | re-mint VMC + VEC | today unconditional; pipeline lets it be policy-gated |
| **Registry / departure** | system | the departing member | choose disposition + publish | runs inside Leave's effects |
| **Cross-community recognition** | foreign issuer | foreign VEC | honor external role | federation; TRQP-resolved |
| **Directory** | member viewer | query | field projection | §5 |

Every one is `verify → facts → evaluate → verdict → effects` with a different policy module, evidence slot, and
effect handler. None needs a bespoke flow.

---

## 9. Why this matters for the build

Because the catalog is *instances*, the expensive machinery is built once and inherited:

- one **verify** stage (all ceremonies),
- one **Verdict** type + **request_more/refer** machinery (all),
- one **versioning / rollback / governance** mechanism (all purposes),
- one **IR + compiler** (per-purpose vocabulary, shared codegen),
- one **Trust Task protocol** shape (see [`vtc-ceremony-protocol.md`](./vtc-ceremony-protocol.md)).

Adding the *sixth* ceremony is writing a policy module, an evidence slot, an effect handler, and a vocabulary —
not a new subsystem.

Runnable policies for every active ceremony — the Rule IR, the compiled `.rego`, and sample `input`
facts with expected verdicts — are in [`examples/`](./examples/): admission phases `phase1` / `phase2`
/ `phase3` / `phase4`, plus member-lifecycle `leave` / `role-change` / `directory`. The authoring
vocabulary and compile mapping are in [`vtc-ceremony-rule-ir.md`](./vtc-ceremony-rule-ir.md).
