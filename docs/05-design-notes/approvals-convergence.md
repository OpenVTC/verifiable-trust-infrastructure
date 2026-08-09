# Approvals convergence — one model instead of three

**Status:** partially landed. The model and its runtime surface shipped in #909;
the shared gate reached the ACL and context REST routes in #912. Still open: the
webvh update route (see below), and the trigger collapse.

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

**#909** (merged as `742340a9`) — `vta_sdk::approvals` (rules, write-time
validation, deterministic Rego synthesis); the canonical
`policy/{list,get,upsert,delete}` family, served for the first time (the VTA had
*no* runtime policy surface); `pnm approvals {list,require,remove,approvers,
explain}` and `pnm policy`; seed-once config; the consent gate resolving
approver sets from the declarative row.

## Not yet landed

**The trigger collapse.** Retire `[auth.step_up]` and
`[[policy.require_consent]]` (boot refusal — a silently dropped floor is a
security downgrade), delete `StepUpMode::{Delegated,DelegatedAny}`,
`AclEntry.step_up_approver` / `step_up_require`, `op_class::ALL`, `op_class_for`,
`resolve_step_up`, and arm (1) of `policy_gate`, leaving the PDP as the only
trigger. Add the offline `vta approvals` break-glass.

### The live gap, and the order to close it

The PDP gate ran *only* in the trust-task dispatcher: `routes/acl.rs::create_acl`
and `routes/did_webvh.rs::update_did_handler` called their operations directly,
so a `requireConsent` rule was **not enforced for a REST caller**. The only thing
gating those routes was the `RequireStepUp` extractor, which is built on
`resolve_step_up` — the function the retirement above deletes.

An earlier draft of this note concluded the two must therefore land as one
atomic change. That was wrong, and the split below is strictly better because it
ships the security fix first:

**Step 1 — add the shared gate (purely additive).** *Landed for the ACL and
context routes.* `approvals::rest_gate()` is called in-handler by `POST /acl`,
`PATCH /acl/{did}`, `POST /acl/{did}/change-role`, `DELETE /acl/{did}` and
`DELETE /contexts/{id}`, with `RequireStepUp` left in place — REST is gated by
both the old floors and the PDP, so nothing is removed and no window opens.

**Still open: `POST /contexts/{ctx}/dids/{scid}`.** The planner parses the gated
payload as `UpdateDidWithDid { did, .. }` and the consent digest is taken over
it, but that handler is addressed by **SCID**. Gating on what it holds would
produce a digest disagreeing with the trust-task path's for the same update, so
an approval obtained over one transport could not be consumed over the other.
Resolve the SCID to its DID before gating; the parity test below extends to it
directly once that lands.

**Step 2 — delete (pure removal).** Everything listed above. REST keeps its
gating from step 1, so nothing has to be sequenced inside this step.

### Shape of the shared gate

The gate must run **in-handler, after body parse** — the consent digest and the
planner both need the payload, which an axum extractor does not have.

`policy_gate` today both *decides* and *shapes a trust-task reject*, because it
threads `&TrustTask<Value>` all the way down to nine `app_error_to_reject(doc, e)`
sites and a handful of `reject_with(doc, …)` sites. Separate the two:

```rust
pub(crate) enum GateReject {
    Reason(RejectReason),  // already-shaped framework reason
    Error(AppError),       // map at the boundary
}
```

`consent_gate`, `require_step_up`, and `initiate_self_step_up` take `&Value`
(the payload) instead of `&TrustTask` and return `RejectReason`; the document is
then only touched at the two call sites that shape a response. Mechanical, and
it leaves the decision logic — the part worth not disturbing — untouched.

REST needs to carry the actionable payload, and today it cannot:
`AppError::StepUpRequired(String)` renders `{error, message, requiredAcr}` with
**no `approveRequest`**, and there is no consent variant at all. Add

```rust
AppError::ApprovalRequired { code: &'static str, details: Value }
```

rendering 403 with `details` merged into the body. That is also what the typed
SDK error below consumes, so the two land on one shape rather than two.

Pair each handler with a test asserting REST and the trust-task path reach the
*same* decision. The absence of exactly that test is why the bypass went
unnoticed.

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
