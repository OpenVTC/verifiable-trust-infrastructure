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
opa eval -d phase4.rego      -i facts.phase4.json      'data.vtc.phase4.decision'
opa eval -d leave.rego       -i facts.leave.json       'data.vtc.leave.decision'
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
