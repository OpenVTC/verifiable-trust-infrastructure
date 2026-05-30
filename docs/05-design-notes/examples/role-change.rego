package vtc.role_change

import future.keywords.if

# Compiled from role-change.ir.json by the VTC Rule IR compiler (illustrative).
# Unlike join, role-change MAY grant "admin" — it is the sanctioned promotion
# path, gated by step-up (and optionally M-of-N). The no-last-admin guard on
# demotion is HOST-enforced around this policy, never in Rego.

# structural totality — compiler-appended
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Standard role change (member / moderator / custom)
decision := {"effect": "allow", "with": {"role": target_role}} if {
	input.evidence.request.target_role != "admin"
}

# P2 Promote to admin — step-up verified
else := {"effect": "allow", "with": {"role": "admin"}} if {
	input.evidence.request.target_role == "admin"
	input.evidence.request.step_up == true
}

# P3 Promote to admin — needs step-up
else := {"effect": "refer", "with": {"queue": "step-up"}} if {
	input.evidence.request.target_role == "admin"
}

# ---- helpers ----
# "$target" in the IR → the requested target_role
target_role := input.evidence.request.target_role
