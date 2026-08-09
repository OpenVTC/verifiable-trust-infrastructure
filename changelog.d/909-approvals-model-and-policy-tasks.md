### vta-sdk 0.21.8 / vta-policy 0.1.3 / vta-service 0.14.17 / vta-cli-common 0.10.25 / pnm-cli 0.11.19 — the declarative approvals model + runtime `policy/*` management (#909)

First slice of the approvals convergence. The VTA answered "does this operation
need an additional human decision?" with three independent subsystems — step-up
floors keyed by a closed list of op-class slugs, `[[policy.require_consent]]`
rules keyed by task type URI, and the messaging-consent registry — using two
config languages over two identifier spaces, only one of which could be changed
at runtime. This lands the shared model and the surface that makes it editable;
the trigger collapse follows.

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
  which matters because the step-up policy surface it starts to replace was
  REST-only in the SDK — an operator on a mediator-only VTA could not read the
  policy that was blocking them.
- **The declarative row stays spec-honest.** Canonical `policy/upsert` treats
  `module` as client-authored and authoritative (`minLength: 1`), so the VTA does
  not synthesize over it: the caller generates the Rego from its rules and sends
  both, and the VTA re-derives from `ext["openvtc.approvals"]` and
  **byte-compares**, refusing a mismatch. The rules an operator reads back are
  therefore guaranteed to describe the policy that actually decides.
- **`pnm policy {list,show,upsert,delete}`** — the hand-authored-Rego escape
  hatch, transport-agnostic.
- `policy/activate` / `policy/active` are deliberately not served (this
  maintainer has no activation pointer — the active set is every enabled row in
  priority order). `policy/evaluate/0.3` is not served either: its `PolicyInput`
  still marks `site` — a vault-flow `SiteTarget` — as required, and there is no
  honest `site` for "would `acl/grant` need approval here". Relaxing that
  upstream is the prerequisite.
- No new Trust Task URIs: every URI above was already published, so the census
  and conformance harnesses pass without growing `UNSPECCED_DISPATCHED_URIS`.
