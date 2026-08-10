# Step-up Policy & Delegated AAL2 — superseded

**This page described a model that no longer exists. See
[Approvals](./approvals.md).**

The `[auth.step_up]` policy floors are retired. A VTA answered "does this
operation need an additional human decision?" three ways — these floors, the
`[[policy.require_consent]]` config block, and the policy rules — resolved
independently of one another. That is how an operator could be told
`auth:step_up_required` for an operation nothing they could read explained.
There is now one model and one place it is enforced.

## What the floors were, and what replaces each part

| Retired | Replacement |
|---|---|
| `[auth.step_up]` in `config.toml` | `[policy.approvals]` (seeded once), then `pnm approvals` at runtime |
| `[[policy.require_consent]]` in `config.toml` | the same `[policy.approvals]` / `pnm approvals` surface |
| A floor keyed on one of 11 op-class slugs (`acl/grant`, `context/delete`, …) | a rule keyed on the **task type URI** itself — finer, and never out of step with what the VTA actually dispatches |
| `mode = "self"` | `pnm approvals require <task-uri> --reauth` |
| `mode = "delegated"` / `"delegated-any"` | `pnm approvals require <task-uri> --consent --set <approver-set>` |
| Per-entry `stepUp.require` override | nothing — a rule may be scoped with `--context`, and an ACL write that still sends the field is refused rather than stored and ignored |
| `allowAal1IfNonEscalating` carve-out | nothing needed — a rule names the exact task, so there is no blunt class to carve an exception out of |
| `auth/step-up/policy/0.2` Trust Task, `GET`/`PUT /step-up/policy`, `pnm step-up policy …`, offline `vta step-up …` | `policy/{list,get,upsert,delete}` Trust Tasks, `pnm approvals`, `pnm policy` |

Delegated step-up — where a *third party* ratified another session's
elevation — has no direct replacement, deliberately. Consent is the stronger
mechanism for the same intent: it carries a threshold, re-checks at consume
time that the approvers are **still** authorized, and puts a VTA-signed
statement of the task's effects in front of the human. A delegated floor did
none of those.

## Migrating

A VTA whose `config.toml` still carries either retired section **will not
start**, and the error names the command that replaces it. That is deliberate:
parsing the section and ignoring it would leave the file asserting that
operations are gated, the operator believing it, and nothing enforcing it.

1. Delete `[auth.step_up]` and any `[[policy.require_consent]]` blocks.
2. Re-declare what they expressed under `[policy.approvals]`, or apply it at
   runtime with `pnm approvals require …`.
3. Start the VTA. On that first boot it also drops the `config:require-consent`
   policy row a previous release synthesized, so nothing survives that the new
   surface cannot show you.
4. `pnm approvals list` — every gated operation, in one place. The old floors
   had no equivalent.

## What did *not* change

The step-up **ceremony** is untouched: `auth/step-up/approve-request/0.2` and
`auth/step-up/approve-response/0.1`|`0.2`, the did-signed and WebAuthn gates,
the pending-step-up store, the bounded elevation window, and the push to an
approver's device all work exactly as before. What changed is only what decides
that a ceremony is needed — which is now the rules, and only the rules.
