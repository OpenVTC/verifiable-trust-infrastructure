# Ceremony policy examples

Concrete, illustrative companions to [`../vtc-ceremony-catalog.md`](../vtc-ceremony-catalog.md). Each ceremony
has its **Rule IR** (`*.ir.json`) and the **compiled Rego** (`*.rego`) that the
[`../vtc-ceremony-rule-ir.md`](../vtc-ceremony-rule-ir.md) compiler emits from it. The Rego reads a `VerifiedFacts`
`input` ([pipeline §3](../vtc-ceremony-pipeline.md)) and returns a `decision` verdict ([pipeline §4](../vtc-ceremony-pipeline.md)).

> These are **design illustrations**, not shipped policy. They use `import future.keywords` for broad
> `regorus`/`opa` compatibility. The no-last-admin guard (leave) and privilege ceiling (join) are **host-enforced**
> around the policy, not in Rego.

## Files

| Ceremony | IR | Rego | Shows |
|---|---|---|---|
| Join | `join.ir.json` | `join.rego` | all four verdicts incl. `request_more` |
| Leave | `leave.ir.json` | `leave.rego` | `actor ≠ subject`, `allow.with.disposition`, `refer` for admin-removes-admin |
| Role-change | `role-change.ir.json` | `role-change.rego` | in-place mutation; `allow` **may** grant `admin` (the sanctioned path, gated by step-up); `refer` = escalation |
| Directory | `directory.ir.json` | `directory.rego` | synchronous read; `allow.with.fields` is a **projection**, not a boolean |

IR convention: a `then.with.disposition` of `"$request"` means "the disposition the actor requested, else
`PolicyDefault`" — the compiler emits the `disposition` helper for it (see `leave.rego`).

## Run them

```sh
# OPA
opa eval -d join.rego        -i facts.join.json        'data.vtc.join.decision'
opa eval -d leave.rego       -i facts.leave.json       'data.vtc.leave.decision'
opa eval -d role-change.rego -i facts.role-change.json 'data.vtc.role_change.decision'
opa eval -d directory.rego   -i facts.directory.json   'data.vtc.directory.decision'
```

(`regorus eval` works equivalently against the same files.)

## Test vectors (sample `input` → expected verdict)

**Join** — `facts.join.json`: a trusted `WitnessCredential`, no code-of-conduct agreement yet.
First-match falls past *Verified human* (agreement missing) to *Almost there*:
```json
{ "effect": "request_more", "with": { "needs": ["agreed:code-of-conduct"], "presentation_definition": { "id": "vtc-join-coc" } } }
```
Add `"agreements": {"code-of-conduct": true}` under `evidence.request` and re-run → *Verified human* matches:
```json
{ "effect": "allow", "with": { "role": "member", "obligations": ["reciprocate_vmc"] } }
```

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
grants `admin` here — that's its job; the privilege ceiling only constrains *join*.)

**Directory** — `facts.directory.json`: an authenticated member viewing another member. Falls to *Member viewer*:
```json
{ "effect": "allow", "with": { "fields": ["did", "role"] } }
```
(An admin viewer matches *Admin viewer* → the full field set. A non-member hits the structural default → `deny`.)
