# Approvals — which tasks need an additional human decision

Some operations should not run on a single credential alone. A VTA expresses
that with **approval rules**: a list keyed on Trust Task type URI, saying that a
task requires either **re-authentication** by the caller or **consent** from
named approvers.

Rules live in the VTA's policy keyspace and are edited at runtime with
`pnm approvals`. No config edit, no restart, and — because the surface rides
Trust Tasks rather than a REST-only endpoint — no requirement that the VTA
advertise REST at all.

## The two kinds of requirement

| | `reauth` | `consent` |
|---|---|---|
| Who decides | the caller, re-proving with a second factor | named approvers, someone other than the caller if you say so |
| Bound to | the caller's **session** (an AAL2 elevation, ~15 min) | the **exact payload**, by digest |
| Good for | "prove it's still you at the keyboard" | "a second person must agree to *this* change" |
| Threshold | n/a | N-of-M, optionally excluding the requester |

Reach for `consent` whenever the point is that a *different party* agrees.
`reauth` has no third party — it raises the assurance of the caller's own
session and nothing more.

> Earlier releases had a third shape: a step-up floor in `delegated` mode, where
> another party ratified and the *caller's session* was then elevated for a
> window. That is consent with weaker binding — approving one act handed the
> caller a period in which every gated act passed — so it is gone. Use `consent`.

## Requiring approval

```bash
# Re-authentication before any ACL grant.
pnm approvals require https://trusttasks.org/spec/acl/grant/0.1 --reauth

# Two people must agree before this VTA's DID document changes,
# and the requester cannot be one of them.
pnm approvals approvers add webvh-approvers did:key:z6MkngmDcnXAck7HQj4ESYhkveodvH6dw1dcx1EzHsL8Ufke
pnm approvals approvers add webvh-approvers did:key:z6MkSecondApproverDeviceKey
pnm approvals require https://trusttasks.org/spec/vta/webvh/dids/update/1.0 \
    --consent --set webvh-approvers --min 2 --exclude-requester
```

Rules can be scoped to contexts with `--context a,b`. An unscoped rule applies
everywhere; a scoped rule wins over an unscoped one for the same task in the
contexts it names.

## Reading it back

```bash
pnm approvals list
pnm approvals explain https://trusttasks.org/spec/acl/grant/0.1
```

`explain` is the one to reach for when a command failed and you want to know
why. It names the rule that applies, who can satisfy it, and — importantly — it
tells you when a rule **cannot** be satisfied, rather than letting you find out
at the next request:

```
https://trusttasks.org/spec/vta/webvh/dids/update/1.0
  context: default
  requires: consent — 2 approval(s) from set `webvh-approvers`, requester excluded
  approvers: 1 member(s) — fewer than the 2 required, so this task can never run
```

## Refusals happen when you write, not when you're blocked

A rule that could never be satisfied is refused at the point you create it:

- an approver set that isn't defined, or is empty
- a threshold larger than the set it draws on
- `--set` / `--min` / `--exclude-requester` on a `--reauth` rule (there is no
  third party to configure)
- two rules for the same task type whose context scopes overlap

This is deliberate. The failure that motivated this design was a step-up floor
in `delegated` mode with no approver registered anywhere — perfectly acceptable
to write, and discovered only when it blocked an operator with an error they
could not act on.

## Seeding a new VTA

`config.toml` can carry the same shape, applied **once**, the first time the VTA
boots without any rules:

```toml
[[policy.approvals]]
task_type = "https://trusttasks.org/spec/acl/grant/0.1"
requires  = "reauth"

[[policy.approvals]]
task_type = "https://trusttasks.org/spec/vta/webvh/dids/update/1.0"
requires  = "consent"
approver_set = "webvh-approvers"
min_approvals = 2
exclude_requester = true

[policy.approver_sets]
webvh-approvers = ["did:key:z6Mkngm…", "did:key:z6MkSecond…"]
```

This is a **seed, not a source of truth**. Once rules exist, the stored rules
win and this block is inert — a restart will not reapply it. That is on purpose:
if config were re-read every boot, a rule you changed at runtime would silently
revert the next time the daemon restarted for an unrelated reason, possibly
weeks later. To re-seed deliberately, delete the rules (`pnm policy delete
approvals`) and restart.

An unsatisfiable seed stops the VTA at boot rather than starting an agent whose
declared protections do not work.

## Enforcement

Rules are evaluated by the Policy Decision Point, which is on only when
`policy.enforcement = true`. With it off, rules are inert — they are stored and
listed, and nothing consults them. Check it before concluding that a rule is
protecting you.

## Hand-authored policy

The rules above compile to Rego. For posture they cannot express — decisions
that turn on side-effect class, exposure, device state, or time — write the Rego
directly:

```bash
pnm policy list
pnm policy upsert --id after-hours --name "After-hours writes" --module ./after-hours.rego
```

Both surfaces write to the same policy keyspace and are evaluated together in
priority order. They do not overlap: `pnm approvals` owns one reserved row
(`approvals`) and refuses to put hand-written Rego in it, and `pnm policy`
refuses to create a second row claiming to carry approval rules. That way the
rules `pnm approvals list` shows are always the rules that actually decide.

## If you lock yourself out

Approval rules apply to policy management too, which is a feature: a `consent`
rule on `https://trusttasks.org/spec/policy/upsert/0.2` gives you two-person
control over changes to the gate itself. It also means a set of approvers whose
keys are all lost can wedge you.

The recovery is the offline break-glass — stop the daemon and edit the rules
directly on the host, with no auth ceremony, the same shape as
`vta services …`. It requires possession of the machine, which is the point.

## See also

- `docs/05-design-notes/approvals-convergence.md` — why there is one model rather
  than three, and what was retired.
- `docs/05-design-notes/acl-scope-semantics.md` — the *act* vs *confer* axis on
  an ACL entry, which decides whether an approver's agreement can carry a
  context the requester lacks.
