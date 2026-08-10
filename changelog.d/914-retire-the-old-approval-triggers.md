### vti-common 0.11.37 / vta-sdk 0.21.10 / vta-config 0.3.2 / vta-policy 0.2.1 / vta-service 0.14.22 / vta-cli-common 0.10.27 / pnm-cli 0.11.21 — one trigger for approvals (#914)

**Breaking.** #912 and #913 put the Policy Decision Point in front of every gated
route, leaving REST enforced by *both* the PDP and the old `[auth.step_up]`
floors. This removes the floors, and the other parallel trigger beside them. A
VTA now answers "does this operation need an additional human decision?" in
exactly one place, from exactly one list of rules — the thing an operator can
read back with `pnm approvals list`.

That reading-back is the point. The convergence started from a `pnm contexts
create` that failed `auth:step_up_required` with nothing an operator could
consult to find out why.

#### Retired

- **`[auth.step_up]`** — the floors: eleven op-class slugs, four modes, and an
  `allowAal1IfNonEscalating` carve-out. Gone with `StepUpPolicy`, `StepUpFloor`,
  `op_class`, the `resolve_step_up` engine, the `RequireStepUp` axum extractor
  and its per-route markers, `require_step_up`, `issue_step_up_challenge`, and
  `step_up_denied_response`.
- **`[[policy.require_consent]]`** — a third trigger, reconciled from the file on
  every boot, so it silently reverted anything changed at runtime.
- **The management surface**: `auth/step-up/policy/0.2` and its dispatch arm,
  `GET`/`PUT /step-up/policy`, `VtaClient::{get,set}_step_up_policy`,
  `pnm step-up policy …`, and the offline `vta step-up …`.

#### Refused, not ignored

Both retired config sections now **fail the load**, with an error naming the
command that replaces them. Parsing and ignoring them would leave the file
asserting that operations are gated, the operator believing it, and nothing
enforcing it. `stepUp.require` on an ACL write is refused for the same reason —
an accepted override would be stored and echoed back on every read as a gate that
does not exist.

And the first boot after upgrade **deletes** the `config:require-consent` policy
row a previous release synthesized. Without that, a VTA upgraded from a release
carrying the block would keep enforcing a `requireConsent` that no config
declares, `pnm approvals list` cannot see, and no command can remove.

#### Two gaps closed on the way out

- **`POST /acl/swap`** was the one gated REST route #912 left on the old trigger,
  because its floor had a carve-out the shared gate has no concept of. Removing
  the extractor without wiring the gate would have made self-service key rotation
  the one ACL mutation a `requireConsent` rule bound over trust tasks and silently
  not over REST. It now calls `rest_gate`, and `SwapAclRequest` serializes
  camelCase so the same rotation digests identically on both transports. The
  legacy DIDComm `handle_swap_acl` — which does not route through the trust-task
  dispatcher — is gated the same way; the floor check was the only approvals check
  it had.
- **`input.consumer.acr` is now `"aal1"` for an un-elevated session**, where it
  used to be omitted. Harmless while the floors did the gating; not harmless now,
  because `input.consumer.acr != "aal2"` is *undefined* against an absent field.
  The rule an operator would naturally write to demand step-up would have silently
  never fired for exactly the sessions it was written to catch. Two integration
  tests default-denied instead of demanding step-up, which is how this surfaced.

#### Behaviour that goes away

Delegated step-up — a *third party* ratifying another session's elevation — has
no direct replacement, deliberately. `[auth.step_up]` was the only thing that
could address an approve-request to someone other than the subject; a rule's
`requireStepUp` is self-approve by construction. `requireConsent` covers the same
intent and covers it better: a threshold, a re-check at consume time that the
approvers are **still** authorized, and a VTA-signed statement of the effects in
front of the human. A delegated floor had none of those.

The step-up **ceremony** itself is untouched — approve-request/approve-response,
the did-signed and WebAuthn gates, the pending store, the bounded elevation
window, the push to an approver's device. Only what decides a ceremony is needed
has changed.

`StepUpMode` survives as the type of `AclEntry.stepUp.require`, a published wire
field, serialisable and inert. Removing the field is its own slice.

#### Still open

An offline `vta approvals` break-glass. The retired `vta step-up` could disable an
over-strict policy from the config file when it had locked everyone out over the
wire; a rule can lock an operator out the same way, and answering that needs a
command reading the policy keyspace directly. Recorded in
`docs/05-design-notes/approvals-convergence.md`.

Docs: `docs/02-vta/approvals.md` is the operator guide;
`docs/02-vta/step-up-policy.md` is now a superseded redirect carrying the
migration table.
