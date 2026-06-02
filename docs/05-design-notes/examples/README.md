# Ceremony policy examples

Concrete, illustrative companions to [`../vtc-ceremony-catalog.md`](../vtc-ceremony-catalog.md). Each ceremony
has its **Rule IR** (`*.ir.json`) and the **compiled Rego** (`*.rego`) that the
[`../vtc-ceremony-rule-ir.md`](../vtc-ceremony-rule-ir.md) compiler emits from it. The Rego reads a `VerifiedFacts`
`input` ([pipeline §3](../vtc-ceremony-pipeline.md)) and returns a `decision` verdict ([pipeline §4](../vtc-ceremony-pipeline.md)).

> These are **design illustrations**, not shipped policy. They use `import future.keywords` for broad
> `regorus`/`opa` compatibility. The no-last-admin guard (leave) and the privilege ceiling (admission
> phases) are **host-enforced** around the policy, not in Rego.

## Files

| Ceremony | IR | Rego | Shows |
|---|---|---|---|
| Phase 1 | `phase1.ir.json` | `phase1.rego` | genesis / initiator self-bootstrap — degenerate single-leaf gate |
| Phase 2 | `phase2.ir.json` | `phase2.rego` | invitation gate parameterised by issuer role — `invitation_issuer_has_role("initiator")` |
| Phase 3 | `phase3.ir.json` | `phase3.rego` | cross-issuer constraint — VIC from a CTA **plus** VRC from a *different* CTA (set-comprehension with `c.issuer != input.evidence.invitation.issuer`) |
| Phase 4 | `phase4.ir.json` | `phase4.rego` | four-clause `all` — member VIC + ≥2 distinct member VRCs (excluding inviter) + IDVC from approved IDVP |
| LKMV maintainer | `lkmv-maintainer.ir.json` | `lkmv-maintainer.rego` | Linux subsystem maintainer addition — single super-maintainer signoff + path-scoped invitation (new leaf `invitation_has_scope`) |
| LKMV merge | `lkmv-merge.ir.json` | `lkmv-merge.rego` | Linux maintainer-authorized merge attestation — one-clause `actor_has_role` gate; new `allow.with.issues_attestation` payload variant ("issuance ceremony" shape) |
| K8s Approver | `k8s-approver.ir.json` | `k8s-approver.rego` | Kubernetes Reviewer → Approver promotion — M-of-N (≥2 distinct approver endorsements) + structural prerequisite (`subject_has_role("reviewer")`); 3-route policy |
| K8s Prow merge | `k8s-prow-merge.ir.json` | `k8s-prow-merge.rego` | Kubernetes Prow bot merge attestation — bot-actor + ≥1 approve + ≥1 lgtm `ReviewAttestation`; 5-route graceful degradation |
| Leave | `leave.ir.json` | `leave.rego` | `actor ≠ subject`, `allow.with.disposition`, `refer` for admin-removes-admin |
| Role-change | `role-change.ir.json` | `role-change.rego` | in-place mutation; `allow` **may** grant `admin` (the sanctioned path, gated by step-up); `refer` = escalation |
| Directory | `directory.ir.json` | `directory.rego` | synchronous read; `allow.with.fields` is a **projection**, not a boolean |

IR convention: a `then.with.disposition` of `"$request"` means "the disposition the actor requested, else
`PolicyDefault`" — the compiler emits the `disposition` helper for it (see `leave.rego`).

## Run them

```sh
# OPA
opa eval -d phase1.rego      -i facts.phase1.json      'data.vtc.phase1.decision'
opa eval -d phase2.rego      -i facts.phase2.json      'data.vtc.phase2.decision'
opa eval -d phase3.rego      -i facts.phase3.json      'data.vtc.phase3.decision'
opa eval -d phase4.rego          -i facts.phase4.json          'data.vtc.phase4.decision'
opa eval -d lkmv-maintainer.rego -i facts.lkmv-maintainer.json 'data.vtc.lkmv_maintainer.decision'
opa eval -d lkmv-merge.rego      -i facts.lkmv-merge.json      'data.vtc.lkmv_merge.decision'
opa eval -d k8s-approver.rego    -i facts.k8s-approver.json    'data.vtc.k8s_approver.decision'
opa eval -d k8s-prow-merge.rego  -i facts.k8s-prow-merge.json  'data.vtc.k8s_prow_merge.decision'
opa eval -d leave.rego           -i facts.leave.json           'data.vtc.leave.decision'
opa eval -d role-change.rego -i facts.role-change.json 'data.vtc.role_change.decision'
opa eval -d directory.rego   -i facts.directory.json   'data.vtc.directory.decision'
```

(`regorus eval` works equivalently against the same files.)

## Test vectors (sample `input` → expected verdict)

**Phase 1** — `facts.phase1.json`: `actor.role == "initiator"`. Matches *Initiator self-bootstrap*:
```json
{ "effect": "allow", "with": { "role": "initiator", "obligations": [] } }
```
Change `actor.role` to anything else and the *Default deny* catch-all fires. Note: Phase 1's "decision"
is moot — per the VTC Bootstrapping spec, the PNM hardcodes this client-side. The IR exists for design
completeness.

**Phase 2** — `facts.phase2.json`: a VIC issued by `did:key:z6MkSomeMember` (`issuer_role: "member"`),
not the initiator. *Invited by initiator* fails on `invitation_issuer_has_role("initiator")` →
*Almost there*:
```json
{ "effect": "request_more", "with": { "needs": ["invitation:from-initiator"], "presentation_definition": { "id": "vtc-phase2-initiator-vic" } } }
```
Change the invitation's `issuer_role` to `"initiator"` (and the issuer DID accordingly) → the first
route matches → `allow` with `role: trustAnchor`.

**Phase 3** — `facts.phase3.json`: a VIC issued by trust anchor `z6MkAnchorA` plus a VRC issued by
**the same** `z6MkAnchorA`. The set comprehension excludes credentials whose issuer equals the VIC
issuer, so `credential_distinct_issuer_count_excl_inviter` yields 0 → *Trust-anchor vouched* fails →
*Almost there*:
```json
{ "effect": "request_more", "with": { "needs": ["invitation:from-trustAnchor", "vrc:from-different-trustAnchor"], "presentation_definition": { "id": "vtc-phase3-ta-vouched" } } }
```
Change the VRC's `issuer` to `z6MkAnchorB` (a different trust anchor with the same community role) →
distinct-issuer count becomes 1 → the first route matches → `allow` with `role: member`. The
`exclude_invitation_issuer: true` flag is what enforces the "different CTA" requirement.

**Phase 4** — `facts.phase4.json`: a member-issued VIC + 1 VRC from another member + 1 IDVC. The gate
needs ≥2 VRCs from distinct *other* members, so the route fails on the VRC count → *Almost there*:
```json
{ "effect": "request_more", "with": { "needs": ["invitation:from-member", "vrc:from-other-members:distinct>=2", "idvc:from-approved-idvp"], "presentation_definition": { "id": "vtc-phase4-member-vouched-idv" } } }
```
Add a second VRC from a different member (issuer ≠ inviter, ≠ the first VRC's issuer) → the route
matches → `allow` with `role: member`. Drop the IDVC instead → the route fails on the IDVC clause and
falls to *Almost there* with `idvc:from-approved-idvp` in `needs`.

**LKMV maintainer** — `facts.lkmv-maintainer.json`: a VIC issued by a super-maintainer, but the
invitation has no `scope` field. *Super-maintainer sponsored with path scope* fails on
`invitation_has_scope` → falls to *Almost there*:
```json
{ "effect": "request_more", "with": { "needs": ["invitation:from-super-maintainer", "invitation:scope-required"], "presentation_definition": { "id": "vtc-lkmv-maintainer" } } }
```
Add `"scope": "drivers/net/ethernet/realtek/**"` to the invitation → the first route matches → `allow`
with `role: maintainer`. The scope itself is informational on the resulting VEC — the policy only
checks that *some* scope was supplied.

**K8s Approver** — `facts.k8s-approver.json`: the candidate currently holds role `reviewer` and has
**one** PromotionEndorsementCredential from `did:key:z6MkApproverA`. *Promoted by quorum of approvers*
fails on the ≥2 distinct-issuers gate; *Awaiting endorsements* matches:
```json
{ "effect": "request_more", "with": { "needs": ["endorsement:from-approver:distinct>=2"], "presentation_definition": { "id": "vtc-k8s-approver-endorsements" } } }
```
Add a second PromotionEndorsementCredential from a different approver DID → distinct-issuer count
becomes 2 → first route matches → `allow` with `role: approver`. Conversely, if the candidate's
`state.subject_member.role` is `"contributor"` (not yet a reviewer), the structural prerequisite fails
at every route and *Not yet a reviewer* fires → `deny`.

**LKMV merge** — `facts.lkmv-merge.json`: the actor's role is `contributor` (not a maintainer). The
one-clause gate fails and the catch-all *Not a maintainer* fires:
```json
{ "effect": "deny", "with": { "code": "lkmv-merge-requires-maintainer-role", "reason": "Only members holding role `maintainer` (or above) may issue MergeAttestations in this community." } }
```
Change `actor.role` to `"maintainer"` → first route matches → `allow` with
`{"issues_attestation": "MergeAttestation", "obligations": ["chain-to-parents"]}`. This `allow`
payload is the new "issuance ceremony" shape (`vtc-ceremony-rule-ir.md` §3) — the host treats it as a
signal to mint a fresh `MergeAttestation` VC, binding the actor's M-DID and current role to the
commit data in `evidence.request`.

**K8s Prow merge** — `facts.k8s-prow-merge.json`: Prow (`actor.role == "merge-bot"`) presents one
`ReviewAttestation` from a Reviewer (an lgtm) but no Approver credential. *Prow merge with approver +
reviewer signoff* fails on the approver gate; *Missing approver signoff* matches:
```json
{ "effect": "request_more", "with": { "needs": ["review:approve-from-approver"] } }
```
Add a `ReviewAttestation` issued by a member holding role `"approver"` → both gates satisfied → first
route matches → `allow` with `{"issues_attestation": "MergeAttestation", "obligations": ["chain-to-reviews",
"chain-to-parents"]}`. The resulting MergeAttestation chains to the underlying ReviewAttestations,
producing a verifiable provenance trail. Drop the actor's role from `"merge-bot"` to `"contributor"`
→ every route fails on the bot prerequisite and *Not the merge bot* fires → `deny`.

**Leave** — `facts.leave.json`: an admin removing a non-admin member. Falls to *Admin removes member*:
```json
{ "effect": "allow", "with": { "disposition": "Tombstone" } }
```
(If `state.subject_member.role` were `"admin"`, *Admin removes admin* matches → `refer` to `second-admin`. If the
removal would empty the admin set, the **host** refuses before effects regardless of this verdict.)

**Role-change** — `facts.role-change.json`: an admin requesting to promote a moderator to `admin`, **without**
step-up. *Standard* doesn't match (target is admin), *Promote-verified* needs `step_up`, so it falls to
*Promote (needs step-up)*:
```json
{ "effect": "refer", "with": { "queue": "step-up" } }
```
(Set `"step_up": true` → *Promote-verified* matches → `allow` with `role: admin`. A standard target like
`"moderator"` matches *Standard role change* → `allow` with `role: <target>`. Note role-change legitimately
grants `admin` here — that's its job; the privilege ceiling only constrains the *admission* phases.)

**Directory** — `facts.directory.json`: an authenticated member viewing another member. Falls to *Member viewer*:
```json
{ "effect": "allow", "with": { "fields": ["did", "role"] } }
```
(An admin viewer matches *Admin viewer* → the full field set. A non-member hits the structural default → `deny`.)
