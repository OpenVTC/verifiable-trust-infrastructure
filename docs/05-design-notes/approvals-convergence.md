# Approvals convergence — one model instead of three

**Status:** partially landed. Slices 1–2 shipped (#909, #910); the trigger
collapse (#3) is designed but not implemented.

## What prompted it

An operator ran `pnm contexts create --admin-did …` against a VTA. The context
was created; the ACL grant behind it failed with `auth:step_up_required`. Three
things about that failure were the actual problem:

1. The policy the operator was reading (`[[policy.require_consent]]`, naming a
   webvh task) was not the policy that fired (`[auth.step_up].floors`, naming
   `acl/grant`). Two config languages over two identifier spaces, answering the
   same question.
2. The reject carried an `approveRequest` — the thing that could have unblocked
   them — and the SDK dropped it, because only the *consent* arm had a typed
   error variant. The step-up arm collapsed to an opaque string.
3. The floor could not be read back at all: step-up policy was REST-only in the
   SDK, and that VTA advertises no REST service. The only way to inspect the
   policy was to overwrite it.

None of these is a bug in isolation. Together they are a design that answers one
question three ways.

## The three subsystems

| | Step-up | Task consent (DTTE) | Messaging consent |
|---|---|---|---|
| Trigger | `[auth.step_up].floors`, keyed by op-class slug — a closed list of 11 | Rego `requireConsent`, keyed by task type URI — open | `consent/request/1.0`, default-deny |
| Approvers | the caller's `AclEntry.stepUp.approver`, or self | `[policy.approver_sets]` in config | registry keyed (platform, context) |
| Bound to | the session (15 min elevation) | the payload digest + state pin + guards | a conversation subject |
| Ceremony | `auth/step-up/approve-response/0.1`, `/0.2` | `task-consent/decision/0.1` | `consent/decision/1.0` |
| Managed by | REST-only PUT + config + offline CLI | config + restart; no API, no CLI | trust task, runtime |

Sequencing explains it: step-up was built for a narrower question (*is this
session strongly enough authenticated?*), then DTTE built a strictly more
general answer (*has this exact act been authorized by named parties?*), and the
two were never reconciled.

## The model

One rule list, keyed on task type URI, carried in the `ext` of one reserved row
in the policy keyspace (`vta_sdk::approvals`):

```jsonc
{ "taskType": "…/spec/acl/grant/0.1", "requires": "reauth" }
{ "taskType": "…/spec/vta/webvh/dids/update/1.0", "requires": "consent",
  "approverSet": "ops", "minApprovals": 2, "excludeRequester": true,
  "contexts": ["openvtc"] }
```

`reauth` → PDP `requireStepUp` → self-elevation. `consent` → PDP
`requireConsent` → the DTTE path, unchanged.

### Delegated step-up is deleted, not ported

`StepUpMode::{Delegated, DelegatedAny}` had another party ratify, and the result
was a **session elevation** for the caller: approve one ACL grant, and for the
next 15 minutes every gated operation passes. That is consent with strictly
worse binding. Consent binds to the payload digest, re-asserts the world at
execution, supports N-of-M and requester exclusion, and shows the approver the
computed effects. There is nothing delegated step-up did better, so the mode is
removed rather than translated, and the migration error says so.

### Why the module is client-authored, and byte-compared

Canonical `policy/upsert` declares `module` (Rego) `minLength: 1` and
authoritative — the maintainer validates it, it does not invent it. So the
client generates the Rego from its rules and sends both; the VTA re-derives from
`ext["openvtc.approvals"]` and refuses the write unless the two are
byte-identical.

The alternative — trust `module`, treat `ext` as decoration — would mean the
rules an operator reads back need not describe the Rego that decides. The
byte-compare is what makes the declarative view *true* rather than advisory. It
also makes `synthesize_rego`'s output a wire compatibility surface: changing the
generated text changes what an older client's row compares against.

### Config is a seed, applied once

The consent policy this supersedes was reconciled from config on **every** boot.
Once the rules are runtime-editable that is a trap: an operator changes a rule,
verifies it, and a restart weeks later — for an unrelated reason — silently
reverts it. The row wins once it exists.

### Write-time refusal

Every unsatisfiable configuration is refused when written: undefined or empty
approver set, threshold larger than its set, consent-only fields on a `reauth`
rule, overlapping guards for one task type. This is the direct answer to the
original failure, where a `delegated` floor with no registered approver was
perfectly legal to write and failed closed at the first request it blocked.

## Landed

- **#909** — `vta_sdk::approvals` (rules, validation, deterministic Rego
  synthesis); the canonical `policy/{list,get,upsert,delete}` family, served for
  the first time (the VTA had *no* runtime policy surface); `pnm policy`.
- **#910** — `pnm approvals {list,require,remove,approvers,explain}`; seed-once
  config; the consent gate resolving approver sets from the row.

## Not yet landed

**The trigger collapse.** Retire `[auth.step_up]` and
`[[policy.require_consent]]` (boot refusal — a silently dropped floor is a
security downgrade), delete `StepUpMode::{Delegated,DelegatedAny}`,
`AclEntry.step_up_approver` / `step_up_require`, `op_class::ALL`, `op_class_for`,
`resolve_step_up`, and arm (1) of `policy_gate`, leaving the PDP as the only
trigger. Add the offline `vta approvals` break-glass.

**This must land together with the REST-gate unification**, and that coupling is
the main thing to know before picking it up. The PDP gate runs *only* in the
trust-task dispatcher: `routes/acl.rs::create_acl` and
`routes/did_webvh.rs::update_did_handler` call their operations directly, so a
`requireConsent` rule is **not enforced for a REST caller** today. The only thing
gating those routes is the `RequireStepUp` extractor, which is built on
`resolve_step_up`. Delete the one without the other and there is a release where
REST is un-gated entirely.

The fix is a shared gate helper both the dispatcher and the REST handlers call,
in-handler rather than as an axum extractor — the consent digest needs the
parsed payload, which an extractor does not have. Roughly thirteen handlers.
Pair each with a test asserting REST and the trust-task path reach the *same*
decision; the absence of such a test is why the bypass went unnoticed.

**The typed error.** `VtaError::ApprovalRequired` carrying the challenge and
`approveRequest`, recognised in `client/mod.rs::trust_task_error` — today only
`auth:consent_required` gets a typed variant and the step-up arm's actionable
payload is discarded. Then `pnm approvals approve <challenge>`: with delegated
step-up gone, the caller *is* the approver for `reauth`, and PNM holds that key.
That closes the loop on the original failure.

## Deferred upstream

- **`policy/evaluate/0.3` is not served.** Its `PolicyInput` still marks `site` —
  a vault-flow `SiteTarget` — as required, inherited from before 0.3 generalised
  the family to any Trust Task. There is no honest `site` for "would `acl/grant`
  need approval here", and fabricating one puts invented data into a security
  decision's input. `vta-policy`'s own schema mirror already carries this as a
  known wart. Relaxing it upstream would let `approvals explain` answer from the
  same `decide()` the gate runs, instead of from the rules.
- **Three ceremony URIs, one shape.** `auth/step-up/approve-response`,
  `task-consent/decision`, and `consent/decision` are all "a signed decision
  echoing a challenge, matched against a pending record, consumed once". Merging
  them into one `approval/decision` family needs a spec in
  `trustoverip/dtgwg-trust-tasks-tf`. Consolidating the handlers internally
  first is what would make adopting it a small change.
