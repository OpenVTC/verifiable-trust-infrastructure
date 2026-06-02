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

## 6. The remaining purposes map cleanly

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

## 7. Why this matters for the build

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
