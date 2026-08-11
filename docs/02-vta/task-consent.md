# Task consent (DTTE) — the approval ceremony

**DTTE** — *Delegated Trust-Task Execution* — is the VTA's answer to "a
different party must agree to *this exact act* before it runs". It is the
mechanism behind a `consent` approval rule.

[Approvals](./approvals.md) covers the **trigger**: which tasks need a human,
written with `pnm approvals require`. This page covers the **ceremony** that
follows — what goes on the wire, who may answer, how long each step lives, and
what an approver actually sees. Read that page first; a rule is what starts any
of this.

> **Naming.** The subsystem is spelled `task_consent` / `requireConsent`
> everywhere in code — `vta-policy/src/consent.rs`, the `task_consent` keyspace,
> `vta-service/src/trust_tasks/task_consent.rs`. "DTTE" is the name in prose.
> It is deliberately **not** the same thing as *messaging consent*
> (`consent/*/1.0`, the `consent_ks` keyspace), which asks whether two parties
> may correspond, and has no CLI surface.

## What it is, in one paragraph

When the Policy Decision Point returns `requireConsent`, the task does not run.
The VTA computes a digest of the exact task URI and payload, parks the request,
and pushes a signed question to each member of the named approver set. Approvers
answer with a Data-Integrity-signed decision echoing a challenge. When the
threshold is met the VTA mints a single-use grant. The requester re-submits the
identical task, the grant is consumed, and only then does the handler run — after
the VTA re-checks that the world has not moved underneath the approval.

The binding is to the **payload**, not the session. That is the whole difference
from re-authentication: approving one act authorizes one act.

## Why it is shaped this way

| Property | What it buys you |
|---|---|
| Bound to a payload digest | An approval authorizes exactly the act described, not a window in which other acts pass |
| Threshold + requester exclusion | N-of-M, with a genuine second party when you ask for one |
| Re-checked at consume | Approvers must **still** be enrolled and the world must still match, or the grant is refused |
| Approver holds no act authority | An approver device can agree without being able to do the thing itself |
| Signed effects | The human is shown what the task will do, computed by dry-running the handler |
| Single-use grants | An approval cannot be replayed into a second execution |

## The wire

Three Trust Task URIs. Only one of them is dispatched.

| URI | Direction | Notes |
|---|---|---|
| `…/spec/task-consent/request/0.1` | VTA → approver | Pushed, VTA-signed. Outbound only — no handler. |
| `…/spec/task-consent/decision/0.1` | approver → VTA | **The only dispatched one.** DI-signed by the approver. |
| `…/spec/task-consent/granted/0.1` | VTA → requester | Fire-and-forget notice. |

There are **no DTTE-specific REST endpoints**. The gate runs on both transports
(`rest_gate` for HTTP handlers, the dispatcher gate for Trust Tasks), but the
ceremony itself is Trust-Task-only.

### The flow

```mermaid
sequenceDiagram
    participant R as Requester
    participant V as VTA
    participant A as Approver device

    R->>V: submit task
    V->>V: PDP → requireConsent; compute payload_digest
    V-->>R: rejected — auth:consent_required (+ challenge, digest, set, threshold)
    V->>A: task-consent/request/0.1 (VTA-signed, pushed)
    A->>A: human compares match code, reads effects
    A->>V: task-consent/decision/0.1 (DI-signed, echoes challenge)
    V->>V: verify proof, check set membership, count threshold
    V->>V: mint single-use grant
    V-->>R: task-consent/granted/0.1 (notice)
    R->>V: re-submit the identical task
    V->>V: consume grant; re-check enrolment, state pin, guards
    V->>R: executed
```

## Timers — all hardcoded

None of these are configurable. Plan your operator experience around them.

| Window | Value | Source |
|---|---|---|
| Pending request TTL | **900 s** (15 min) | `trust_tasks/policy_gate.rs:43` |
| Grant TTL once minted | **600 s** (10 min) | `trust_tasks/task_consent.rs:23` |
| Push deliver-by | 300 s | `trust_tasks/consent_request.rs:12` |
| CLI wait timeout / poll | 300 s / 3 s | `vta-cli-common/src/consent.rs:53, 44` |

So an approver has fifteen minutes to answer, and the requester ten minutes to
consume the result. Expired pendings are swept by
`policy::consent::sweep_expired` (`vta-service/src/server.rs:1223`).

## The two digests

This trips people up, so it is worth being explicit. There are two, and they are
not interchangeable (`vta-policy/src/consent.rs:50-91`).

- **`payload_digest`** — SHA-256 over `DIGEST_DOMAIN ‖ len(uri) ‖ uri ‖
  len(JCS(payload)) ‖ JCS(payload)`. **Executor-internal; never leaves the
  process.** It keys `pending:` and `grant:` rows. It cannot be the salted one,
  because the gate must recompute it on a re-submit *before* it knows the
  challenge.
- **`wire_digest`** — the same, salted with the per-request challenge. **The only
  digest an approver ever sees.**

The salt matters: an unsalted digest over a low-entropy payload is a confirmation
oracle. "Deactivate `did:webvh:abc…`" has essentially one canonical form, so
anyone observing the digest in transit could guess the operation and hash to
check. Both screens still derive the same value because both hold the challenge.

The type URI is inside the digest and **length-prefixed**, so the URI/payload
boundary cannot be shifted. Without that, `dids/update`, `dids/rotate-keys` and a
deactivate — all plausibly `{"did":…,"contextId":…}` — would share a digest, and
an approval for the benign one would authorize the destructive one.

### The match code an operator compares

Six hex characters, UI-only, no wire field. It is derived from the **decoded
digest bytes**, not from the multibase string
(`vta-mobile-core/src/consent.rs:79`).

That distinction is load-bearing. A `digestMultibase` always begins `zQm` — the
base58btc marker plus the sha2-256 multihash prefix, identical for every digest
ever produced. Slicing the encoded string would spend half a six-character code
on a constant, leaving ~17.6 bits where the operator believes they are comparing
~35, while still *looking* like six random characters. An attacker searching
offline for a colliding render would face ~195k candidates instead of ~60
billion.

> **Interop hazard.** The digest moved from bare hex to `digestMultibase` in
> trust-tasks 0.4 (#911). Any approver stack that computes a digest independently
> — the browser plugin, anything on an older `vta-mobile-core` — **must move in
> lockstep**. A mismatched pair produces an approval that is given, accepted by
> the human, and then silently never takes effect. In-flight pendings and grants
> are invalidated by the encoding change; they TTL out in 900 s.

## Who may approve

**Membership in the approver set the policy names is sufficient.** Since #907, an
approver device does **not** additionally need an ACL entry to deliver its
decision.

That is the intended model: an approver holds no authority to *act* — the point
of the act-vs-confer axis in [ACL scope semantics](../05-design-notes/acl-scope-semantics.md)
— so it has no reason to hold an ACL entry. When the ACL turns a sender away and
the envelope names a ceremony task, the transport dispatches it over
`Role::Monitor` with no contexts: authorized nowhere, no session row minted. It
is a fallback, not an override — an enrolled sender keeps the claims its entry
earns it, and every non-ceremony task from an unenrolled DID is refused as
before.

You still want a real ACL entry in one case: when the approver must **confer** a
context the requester lacks. Approve-authority for delegation is resolved from
live ACL state at the moment the grant is minted.

Ceremony tasks are also exempt from PDP re-gating (`trust_tasks/ceremony.rs:48`)
— otherwise approving would require approving, forever.

## What the approver is shown

Not just a digest. The VTA dry-runs the handler it is about to invoke and signs
the resulting **effects** (`vta-policy/src/effects.rs:31`) into the request
document, alongside a **state pin** (`:94`) recording the world the effects were
computed against.

The `kind` set on an effect is **open**: a surface must render a kind it does not
recognise, always showing `summary`. Do not switch exhaustively on it.

## Consuming a grant — the three re-checks

A grant is minted against a world that may have moved by the time it is used. On
the re-submit, `consent_gate` re-checks all three (`policy_gate.rs:255+`):

1. **Policy.** The gate runs on every submit including the re-submit, so the
   current decision applies — a policy tightened during the approval window
   takes effect.
2. **Enrolment.** The approvers who signed must *still* be members of the set the
   *current* policy names, and must still meet its threshold. The approver set is
   resolved from the declarative row first, config only as fallback — which is
   why `pnm approvals approvers` takes effect without a restart.
3. **Data.** The state pin and the executor's own guards.

The grant is consumed **before** those checks can refuse it. Single-use is
single-use even when the outcome is a refusal; re-submitting mints a fresh
request and asks the approver again against the world as it now is.

## Pending vs denied — why the CLI stops polling

There is no read-only status surface for task consent, so "approved yet?" can
only be asked by submitting again. What that does depends on state:

- **Pending** — the gate recognises the payload, returns the **same** challenge,
  and deliberately does not re-notify. Polling cannot ring the approver's device.
- **Denied or lapsed** — the pending record is **deleted**. The next submit finds
  nothing, raises a *new* question, and pushes again.

`vta_cli_common::consent::with_consent` therefore stops the instant the challenge
changes. Continuing would convert a "no" into repeated prompts — the habituation
attack where a prompt an attacker can summon on demand is worth more than one
they must wait for. Timing out is not failure: the request stays pending, so
re-running resumes on the same challenge.

## Using it

### 1. Turn the PDP on

Rules are inert without it. `config.toml`, then restart:

```toml
[policy]
enforcement = true
```

Default is `false` (`vta-config/src/lib.rs:24`). There is no runtime surface —
the config-patch registry (`vta-service/src/operations/config.rs:54-77`) carries
only `vta_did`, `vta_name`, `public_url`, so `pnm config update` cannot reach it.

> `pnm approvals list` and `explain` do **not** display the enforcement state.
> A satisfiable rule can print cleanly while nothing is gated. Check the running
> config independently.

### 2. Declare the rule

```bash
pnm approvals approvers add ops did:key:z6Mkngm…
pnm approvals approvers add ops did:key:z6MkSecond…

pnm approvals require https://trusttasks.org/spec/vta/webvh/dids/update/1.0 \
    --consent --set ops --min 2 --exclude-requester

pnm approvals explain https://trusttasks.org/spec/vta/webvh/dids/update/1.0
```

`pnm approvals` and `pnm policy` are **Trust-Task-only**. The SDK's REST arm for
`/policies` is unimplemented (`vta-sdk/src/client/policy.rs:10-17`) and no such
axum route exists, so a REST-transport client gets a **404**, not a permission
error. Use a DIDComm- or TSP-transport client.

### 3. Enrol an approver device

The decision signer lives in `vta-mobile-core/src/consent.rs`
(`build_task_consent_decision_did_signed`). **No Rust client crate can sign a
decision**, so `pnm` shows the code and waits for a device to answer.

For a single-operator posture, set `exclude_requester = false` and put the
CLI's own DID in the set.

### 4. Run a gated task

The CLI submits, prints the match code, and waits (`did-mgmt dids edit` is wired
up; the `with_consent` helper is generic and other commands can adopt it).
Approve on the device, and the re-submit goes through.

## Seeding a fresh VTA

`[policy.approvals]` / `[policy.approver_sets]` in `config.toml` are applied
**once**, on the first boot with no declarative row. After that the row wins and
the block is inert — see [Approvals § Seeding](./approvals.md#seeding-a-new-vta)
for why re-reading every boot was the trap this replaced.

**`vta setup --from` cannot carry them.** `WizardInputs` is
`#[serde(deny_unknown_fields)]` with no `policy` field
(`vta-service/src/setup/from_toml.rs:58`), so a `[policy]` section in the wizard
TOML is a hard parse error. Setup always emits `policy: Default::default()` —
PDP off, no rules, no sets. The seed goes into the **generated** `config.toml`,
hand-edited before first boot.

An unsatisfiable seed stops the VTA at boot rather than starting an agent whose
declared protections do not work.

## Migrating from `[[policy.require_consent]]`

The retired config block is a **hard boot failure**, not a warning
(`vta-config/src/lib.rs:89`). The error names the replacement.

Your previous rules are also **gone, not orphaned**: the first boot after upgrade
runs `remove_stale_config_consent_policy` (`vta-service/src/server.rs:824`), a
one-way cleanup deleting the `config:require-consent` row. It has to — the old
block was reconciled from file every boot, so removing the config without the
cleanup would strand a `requireConsent` that no config declares, `pnm approvals
list` cannot see, and no command can remove. Re-declare with `pnm approvals
require`.

## Audit

Every ceremony step is audited via `vta_audit::record_consent` (`vta-audit/src/lib.rs:119`):
`consent.required` → `consent.decision` → `consent.granted` → `consent.consumed`.
Denials are recorded with a reason (e.g.
`denied:approver_no_longer_authorized`).

## Failure codes

| Code | Meaning |
|---|---|
| `auth:consent_required` | A rule applies; a pending was raised. Answer on an approver device. |
| `auth:consent_stale` | The grant no longer authorizes — enrolment, policy, or state moved. |
| `auth:step_up_required` | A `reauth` rule, not consent. Re-authenticate. |

Over REST these arrive as `AppError::ApprovalRequired { code, details }`. Over
Trust Tasks the SDK surfaces `VtaError::ConsentRequired`, carrying
`payload_digest`, `challenge`, `approver_set`, `min_approvals` and
`exclude_requester` — detection keys on `details.reason`, deliberately not on the
top-level `code` (which is `taskFailed` for every gated task).

## Known gaps

- **No CLI-side decision signer.** Remote approval only.
- **No read-only pending-status task.** "Approved yet?" is a re-submit.
- **`policy/evaluate/0.3` is not served** — its `PolicyInput.site` is required
  with no honest value for "would this task need approval". `pnm approvals
  explain` answers from the rules instead.
- **Three ceremony families, one shape.** `auth/step-up/approve-response`,
  `task-consent/decision` and `consent/decision` are all "a signed decision
  echoing a challenge, matched against a pending, consumed once". Merging them
  needs an upstream spec.

## See also

- [Approvals](./approvals.md) — the rules that trigger this.
- [Approvals convergence](../05-design-notes/approvals-convergence.md) — why
  there is one model rather than three, and what was retired.
- [ACL scope semantics](../05-design-notes/acl-scope-semantics.md) — act vs
  confer, which decides whether an approver can carry a context the requester
  lacks.
