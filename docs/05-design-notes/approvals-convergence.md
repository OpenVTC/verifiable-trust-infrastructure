# Approvals convergence — one model instead of three

**Status:** partially landed. The model and its runtime surface shipped in #909;
the shared gate reached every gated REST route in #912 and #913. Still open: the
trigger collapse.

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

## The offline break-glass

*Landed (#915).* `vta approvals {list,remove,disable}` and
`vta policy {list,delete}` read and write the policy keyspace directly, the way
`vta services …` does for the DID document. This is what the retired
`vta step-up disable` used to be for the config floors.

Two design choices worth keeping:

- **Read-mostly.** There is no offline `require`. Adding a gate is never an
  emergency, and a break-glass path that can install one is a way to plant a
  control that never passed through the authenticated surface.
- **`approvals list` surfaces hand-authored modules by name.** The declarative
  view deliberately refuses to show Rego it did not generate — a row whose module
  said something other than its rules would make the printout a lie — but an
  operator diagnosing a lockout who sees an empty rule list will otherwise
  conclude nothing is gating them. `vta policy list/delete` is the other half:
  a hand-authored module can deny the `policy/delete` that would remove it.

Writing tests for it found two defects in the first draft, both in the same
place: `list` and `disable` each parsed the declarative row *before* acting, so
neither worked on an unparseable row — the state where every other command has
already failed and this is all that is left. Parsing is now best-effort in both.

## Not yet landed

**`AclEntry.step_up_approver` / `step_up_require`.** Published wire fields across
~250 VTA-side references (`operations/acl.rs` alone has 49) plus CLI flags.
`step_up_require` is now *refused* on write rather than stored-and-ignored, so
the field grants nothing, but the removal is its own slice with its own wire
consequences.

**`trusted_presentation_verifiers`.** A config allowlist of verifier DIDs that
auto-consent credential presentation; everything else defers
(`operations::credential_exchange::ConsentPolicy`). Config-only, no runtime
surface, invisible to `pnm approvals list` — the same defect class this
convergence closed twice, on the credential-presentation path rather than the
task path. It asks a genuinely different question ("may this verifier see my
credentials?" vs "does this task need a human?"), so folding it in needs a design
call rather than a mechanical port.

**`policy/evaluate/0.3`.** Still not served: its `PolicyInput` marks `site` (a
vault-flow `SiteTarget`) required, and there is no honest value for "would
`acl/grant` need approval". Needs an upstream schema relaxation;
`pnm approvals explain` answers from the rules instead.

### The live gap, and the order to close it

The PDP gate ran *only* in the trust-task dispatcher: `routes/acl.rs::create_acl`
and `routes/did_webvh.rs::update_did_handler` called their operations directly,
so a `requireConsent` rule was **not enforced for a REST caller**. The only thing
gating those routes was the `RequireStepUp` extractor, which is built on
`resolve_step_up` — the function the retirement above deletes.

An earlier draft of this note concluded the two must therefore land as one
atomic change. That was wrong, and the split below is strictly better because it
ships the security fix first:

**Step 1 — add the shared gate (purely additive).** *Landed.* `rest_gate()` is
called in-handler by `POST /acl`, `PATCH /acl/{did}`,
`POST /acl/{did}/change-role`, `DELETE /acl/{did}`, `DELETE /contexts/{id}` and
`POST /contexts/{ctx}/dids/{scid}/update`, with `RequireStepUp` left in place — REST is gated by
both the old floors and the PDP, so nothing is removed and no window opens.

The webvh update route needed one extra step: it is addressed by **SCID** while
the gate's payload is keyed on the DID, so it resolves the SCID first
(`resolve_webvh_did`) and gates on `{did, …body}` — the shape the trust-task
path sends. Gating on the SCID would have digested the same update differently
per transport, so an approval obtained over one could not be consumed over the
other: a subtler failure than no gate at all.

**Step 2 — delete (pure removal).** *Landed (#914).* REST kept its gating from
step 1, so nothing had to be sequenced inside this step. Two things turned out
not to be pure removal:

- **`POST /acl/swap` had no gate behind its extractor.** Step 1 skipped it
  because its floor carried the `allowAal1IfNonEscalating` carve-out, which the
  shared gate has no concept of. Deleting the extractor without wiring the gate
  would have made self-service key rotation the one ACL mutation a
  `requireConsent` rule bound over trust tasks and silently not over REST. Same
  for the legacy DIDComm `handle_swap_acl`, which does not route through the
  dispatcher: the floor check was the only approvals check it had. Both now call
  `rest_gate`.
- **`input.consumer.acr` was omitted for an un-elevated session**, so
  `input.consumer.acr != "aal2"` — the rule an operator would naturally write to
  demand step-up — was *undefined* rather than true, and would silently never
  fire for exactly the sessions it targeted. Harmless while the floors did the
  gating. It now reports `"aal1"`.

The retirement also had to reach *past* the code: a VTA upgraded from a release
carrying `[[policy.require_consent]]` would have kept enforcing the
`config:require-consent` row its last boot synthesized, with nothing left able to
explain or remove it. The reconciler became a one-way cleanup that deletes the row
on the first boot after upgrade.

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
