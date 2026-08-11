### vta-policy 0.2.2 — document the consent ceremony, and retire the step-up vision page (#927)

The approvals convergence documented the **trigger** — `docs/02-vta/approvals.md`
covers which tasks need a human and how to say so — and left the **ceremony**
undocumented. Nothing described what actually goes on the wire once a
`requireConsent` rule fires, so the operational facts that decide whether an
operator can run the feature lived only in changelog fragments and source
comments.

## New: `docs/02-vta/task-consent.md`

The DTTE reference. The wire (three URIs, one of them dispatched), the four
hardcoded timers, the two-digest design and why one is salted, who may approve,
what the approver is shown, the three re-checks at consume, and the
pending-vs-denied distinction that decides when a client may re-submit.

It also writes down four things that were only discoverable by reading source:

- `pnm approvals` / `pnm policy` are **Trust-Task-only**. The SDK's REST arm is
  unimplemented and no `/policies` route exists, so a REST-transport client gets
  a **404** rather than a permission error — which reads as a broken deployment.
- `vta setup --from` **cannot** carry `[policy]`. `WizardInputs` is
  `deny_unknown_fields`, so a `[policy]` section is a hard parse error, and setup
  always emits `policy: Default::default()`. The seed goes in the generated
  `config.toml`.
- `pnm approvals list` / `explain` do **not** surface enforcement state. A
  satisfiable rule prints cleanly while nothing is gated.
- Your pre-upgrade consent rules are **deleted, not orphaned** — first boot runs
  `remove_stale_config_consent_policy`.

The trust-tasks 0.4 `digestMultibase` hazard is promoted here too. It was
documented in a fragment that a release collates and buries, and it is a live
interop trap: a mismatched approver stack produces an approval that is given,
accepted by the human, and then silently never takes effect.

## Removed: `docs/vta-step-up-art-of-the-possible.html`

A forward-looking vision page for a model that no longer exists. Doubly stale:
its headline principle ("Delegated modes mean a different person or device must
sign off") described the mechanism #914 deleted, and its roadmap listed "M-of-N
quorum on one challenge" as *next* when consent has shipped it — with tighter
binding — for some time. Left in place it argues for the wrong design.

Replaced by `docs/02-vta/task-consent-infographic.html`, which keeps the format
and tells the accurate story: why payload-binding beats session-elevation, the
six-step ceremony, the timers, and an honest live-vs-gap capability read rather
than a roadmap.

## Corrections

- `approvals-convergence.md`'s status header still read *"partially landed …
  Still open: the trigger collapse"* — landed in #914, with the same file saying
  so two sections down. The `## Not yet landed` heading had also swallowed the
  fully-landed REST-gap narrative; the genuine deferrals now sit under
  `## Deferred` and the landed sequencing is its own section.
- `docs/README.md` never listed `approvals.md` at all — not in the task table,
  not in the Part II contents — nor `approvals-convergence.md` in Part V. All
  four pages are now indexed.
- `CLAUDE.md` gained an **Approvals + task consent (DTTE)** integration flow. It
  was the one wire-level flow with its own Trust Task family missing from that
  map, so an agent reading the file found the retired config shape nowhere
  contradicted.
- `vta-policy/src/consent.rs` now expands DTTE in its module header and points at
  the operator doc. The acronym appeared ~14 times in the workspace, all prose,
  and never in the subsystem it names — so grepping the word an operator would
  use found nothing.
