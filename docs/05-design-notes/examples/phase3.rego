package vtc.phase3

import future.keywords.if
import future.keywords.in

# Compiled from phase3.ir.json by the VTC Rule IR compiler (illustrative).
# Crypto (signatures, holder-binding, revocation, issuer-trust) is resolved by the
# host BEFORE evaluation; this policy reasons only over verified facts in `input`.
# The Verify stage additionally decorates each credential with
# `issuer_role_in_community` (looked up against the community ACL by issuer DID).
# Phase 3 admits a new member when a trust anchor invites them AND a DIFFERENT
# trust anchor has independently established a relationship with them.
# The privilege ceiling (no admin via an admission ceremony) is host-enforced, not encoded here.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Trust-anchor vouched
decision := {"effect": "allow", "with": {"role": "member", "obligations": ["reciprocate_vmc"]}} if {
	has_valid_invitation
	input.evidence.invitation.issuer_role == "trustAnchor"
	credential_distinct_issuer_count_excl_inviter("VerifiableRelationshipCredential", "trustAnchor") >= 1
}

# P2 Almost there (catch-all)
else := {"effect": "request_more", "with": {"needs": ["invitation:from-trustAnchor", "vrc:from-different-trustAnchor"], "presentation_definition": {"id": "vtc-phase3-ta-vouched"}}} if {
	true
}

# ---- helpers ----
has_valid_invitation if {
	input.evidence.invitation.verified
	not input.evidence.invitation.consumed
}

# Count of DISTINCT issuer DIDs across credentials of `t` whose issuer is trusted
# and holds `role` in this community, EXCLUDING any whose issuer equals the
# invitation issuer (so a CTA can't both invite and self-vouch).
credential_distinct_issuer_count_excl_inviter(t, role) := count({c.issuer |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
	c.issuer != input.evidence.invitation.issuer
})
