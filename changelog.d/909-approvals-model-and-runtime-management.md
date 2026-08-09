### vta-config 0.3.1 / vta-sdk 0.21.9 / vta-policy 0.1.4 / vta-service 0.14.18 / vta-cli-common 0.10.26 / pnm-cli 0.11.20 — one approval model, manageable at runtime (#909)

The VTA answered "does this operation need an additional human decision?" with
three independent subsystems — step-up floors keyed by a closed list of eleven
op-class slugs, `[[policy.require_consent]]` rules keyed by task type URI, and
the messaging-consent registry — using two config languages over two identifier
spaces, only one of which could be changed at runtime. This is the first half of
collapsing them. Additive throughout: nothing is retired, no path is un-gated.

- **New `vta_sdk::approvals`** — one `ApprovalRule` list keyed on task type URI
  (`requires: "reauth" | "consent"`, optional approver set, threshold,
  `excludeRequester`, per-context scoping) plus the named approver sets, and the
  deterministic Rego synthesizer both the CLI and the VTA derive from.
  Validation is **write-time**: an unknown or empty approver set, a threshold no
  set could meet, a consent-only field on a `reauth` rule, or two rules whose
  guards overlap are all refused when an operator writes them, not discovered by
  the first caller they block.
- **Runtime PDP management on the canonical `policy/*` family** —
  `policy/list/0.2`, `policy/get/0.1`, `policy/upsert/0.2`, `policy/delete/0.1`,
  all already published upstream, none previously served here. The VTA had **no**
  runtime policy surface at all; changing what the PDP enforced meant editing
  `config.toml` and restarting. Reachable over DIDComm and TSP as well as REST,
  which matters because the step-up policy surface this begins to replace was
  REST-only in the SDK — an operator on a mediator-only VTA could not read the
  policy that was blocking them.
- **`pnm approvals {list,require,remove,approvers,explain}`** — the rules and
  their approver sets, edited live. Each command is a read-modify-write of the
  reserved policy row carrying `expectedVersion`, so two operators editing at
  once collide instead of silently overwriting each other. `explain` names the
  rule that applies, who can satisfy it, and says outright when a rule *cannot*
  be satisfied.
- **`pnm policy {list,show,upsert,delete}`** — the hand-authored-Rego escape
  hatch. The two surfaces cannot collide: `approvals` owns one reserved row and
  refuses hand-written Rego in it, and `policy` refuses to create a second row
  claiming to carry approval rules.
- **The declarative row stays spec-honest.** Canonical `policy/upsert` treats
  `module` as client-authored and authoritative (`minLength: 1`), so the VTA does
  not synthesize over it: the caller generates the Rego from its rules and sends
  both, and the VTA re-derives from `ext["openvtc.approvals"]` and
  **byte-compares**, refusing a mismatch. The rules an operator reads back are
  therefore guaranteed to describe the policy that actually decides.
- **`[policy.approvals]` / `[policy.approver_sets]` are a seed, applied once**
  when the VTA boots without a declarative row — the bring-up path for a fresh
  or IaC-provisioned VTA. Deliberately **not** the reconcile-every-boot
  behaviour of the consent policy it supersedes: once rules are editable at
  runtime, re-reading the file every boot means a restart weeks later silently
  reverts an operator's change. Pinned by a test. An unsatisfiable seed stops the
  VTA at boot rather than starting an agent whose declared protections do not
  work.
- The consent gate resolves approver sets from the declarative row first, falling
  back to config, so `pnm approvals approvers add` takes effect without a
  restart while a VTA whose sets are still in config keeps working. The row sits
  at priority 200, above the legacy config-synthesized consent row (100) — a task
  named by both would otherwise tie, and ties break by keyspace iteration order.
- `policy/activate` / `policy/active` are deliberately not served (this
  maintainer has no activation pointer — the active set is every enabled row in
  priority order). `policy/evaluate/0.3` is not served either: its `PolicyInput`
  still marks `site` — a vault-flow `SiteTarget` — as required, and there is no
  honest `site` for "would `acl/grant` need approval here". Relaxing that
  upstream is the prerequisite.
- No new Trust Task URIs: every URI above was already published, so the census
  and conformance harnesses pass without growing `UNSPECCED_DISPATCHED_URIS`.
- Docs: `docs/02-vta/approvals.md` (operator guide),
  `docs/05-design-notes/approvals-convergence.md` (why one model instead of
  three, what is retired, and what remains).
