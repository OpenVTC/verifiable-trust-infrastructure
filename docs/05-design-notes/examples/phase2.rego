package vtc.phase2

import future.keywords.if
import future.keywords.in

# Compiled from phase2.ir.json by the VTC Rule IR compiler (illustrative).
# Crypto (signatures, holder-binding, revocation, issuer-trust) is resolved by the
# host BEFORE evaluation; this policy reasons only over verified facts in `input`.
# Phase 2 admits community trust anchors invited by the initiator.
# The privilege ceiling (no admin via an admission ceremony) is host-enforced, not encoded here.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Invited by initiator
decision := {"effect": "allow", "with": {"role": "trustAnchor", "obligations": ["reciprocate_vmc"]}} if {
	has_valid_invitation
	input.evidence.invitation.issuer_role == "initiator"
}

# P2 Almost there (catch-all)
else := {"effect": "request_more", "with": {"needs": ["invitation:from-initiator"], "presentation_definition": {"id": "vtc-phase2-initiator-vic"}}} if {
	true
}

# ---- helpers ----
has_valid_invitation if {
	input.evidence.invitation.verified
	not input.evidence.invitation.consumed
}
