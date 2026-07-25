# Default VTA Policy Decision Point baseline.
#
# Boot-installed (id "default", priority 0) only when the policy keyspace is
# empty, so an operator's uploads are never clobbered. Operators layer
# higher-priority policies above this to tighten posture; the first policy whose
# `decision` rule fires wins.
#
# MIGRATION-SAFE BASELINE. Enforcement (wiring evaluate_policy into the dispatch
# path) lands in a later change. Until then this policy is exercised only by
# `policy/evaluate` dry-runs. It is intentionally permissive so that when
# enforcement is switched on, existing flows keep working and operators tighten
# deliberately (expand-before-contract). The engine itself is deny-by-default:
# if this policy is removed and nothing else matches, `decide()` denies.
#
# The rule bodies below double as worked examples of the two authoritative
# SPEC §7.3 dimensions a policy can gate on:
#   input.request.sideEffects        — "none" | "mutating" | "destructive"
#   input.request.exposure.discloses — "none" | "metadata" | "secret"
#   input.request.exposure.actsAsSubject — boolean
# plus input.request.typeUri, input.request.subject, input.consumer.*.

package vta.policy

import rego.v1

# Read-only / idempotent tasks: allow silently.
decision := {"decision": "allow", "explanation": "read-only baseline"} if {
	input.request.sideEffects == "none"
}

# State-changing / disclosing / acting tasks: allowed by this baseline, but this
# is exactly where an operator policy would return "requireStepUp" (for
# destructive or secret-disclosing ops) or "requireConsent" (with an
# approverSet, optionally excludeRequester) instead.
decision := {
	"decision": "allow",
	"explanation": "default baseline — layer a higher-priority policy to require step-up or consent",
} if {
	input.request.sideEffects != "none"
}
