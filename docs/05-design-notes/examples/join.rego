package vtc.join

import future.keywords.if
import future.keywords.in

# Compiled from join.ir.json by the VTC Rule IR compiler (illustrative).
# Crypto (signatures, holder-binding, revocation, issuer-trust) is resolved by the
# host BEFORE evaluation; this policy reasons only over verified facts in `input`.
# The privilege ceiling (no admin via join) is host-enforced, not encoded here.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Invitation (unlisted)
decision := {"effect": "allow", "with": {"role": "member", "obligations": ["reciprocate_vmc"]}} if {
	has_valid_invitation
}

# P2 Verified human
else := {"effect": "allow", "with": {"role": "member", "obligations": ["reciprocate_vmc"]}} if {
	cred_trusted("WitnessCredential")
	agreed("code-of-conduct")
}

# P3 Almost there
else := {"effect": "request_more", "with": {"needs": ["agreed:code-of-conduct"], "presentation_definition": {"id": "vtc-join-coc"}}} if {
	cred_trusted("WitnessCredential")
}

# P4 Open review (catch-all)
else := {"effect": "refer", "with": {"queue": "moderator"}} if {
	true
}

# ---- helpers ----
cred_held(t) if {
	some c in input.evidence.presentation.credentials
	c.type == t
	c.status == "valid"
}

cred_trusted(t) if {
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.status == "valid"
}

endorsement_count := count([c |
	some c in input.evidence.presentation.credentials
	c.type == "EndorsementCredential"
])

has_valid_invitation if {
	input.evidence.invitation.verified
	input.evidence.invitation.issuer_trusted
	not input.evidence.invitation.consumed
}

agreed(tag) if {
	input.evidence.request.agreements[tag] == true
}
