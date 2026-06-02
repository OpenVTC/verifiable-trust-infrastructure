package vtc.lkmv_maintainer

import future.keywords.if

# Compiled from lkmv-maintainer.ir.json by the VTC Rule IR compiler (illustrative).
# Linux subsystem-maintainer addition: a super-maintainer issues a VTC invitation
# credential (VIC) that grants the `maintainer` role for a specific code path
# (e.g., "drivers/net/ethernet/realtek/**"). The promotion is single-sponsor
# (M-of-1) — Linux governance defers heavily to existing maintainers' judgment.
# The privilege ceiling (no admin from a capability-escalation ceremony) is
# host-enforced, not encoded here. `maintainer` is not `admin`, so it holds.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Super-maintainer sponsored with path scope
decision := {"effect": "allow", "with": {"role": "maintainer", "obligations": ["accept-maintainership"]}} if {
	has_valid_invitation
	input.evidence.invitation.issuer_role == "super-maintainer"
	invitation_has_scope
}

# P2 Almost there (catch-all)
else := {"effect": "request_more", "with": {"needs": ["invitation:from-super-maintainer", "invitation:scope-required"], "presentation_definition": {"id": "vtc-lkmv-maintainer"}}} if {
	true
}

# ---- helpers ----
has_valid_invitation if {
	input.evidence.invitation.verified
	not input.evidence.invitation.consumed
}

invitation_has_scope if {
	input.evidence.invitation.scope
	input.evidence.invitation.scope != ""
}
