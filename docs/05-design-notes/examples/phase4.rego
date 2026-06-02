package vtc.phase4

import future.keywords.if
import future.keywords.in

# Compiled from phase4.ir.json by the VTC Rule IR compiler (illustrative).
# Crypto (signatures, holder-binding, revocation, issuer-trust) is resolved by the
# host BEFORE evaluation; this policy reasons only over verified facts in `input`.
# Phase 4 admits new members when an existing member invites them AND they have
# verified relationships with at least 2 other distinct members (excluding the
# inviter) AND they hold an Identity Verification Credential from an approved IDVP.
# The privilege ceiling (no admin via an admission ceremony) is host-enforced, not encoded here.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Member-vouched + ID-verified
decision := {"effect": "allow", "with": {"role": "member", "obligations": ["reciprocate_vmc"]}} if {
	has_valid_invitation
	input.evidence.invitation.issuer_role == "member"
	credential_distinct_issuer_count_excl_inviter("VerifiableRelationshipCredential", "member") >= 2
	credential_distinct_issuer_count("IdentityVerificationCredential", "identityVerificationProvider") >= 1
}

# P2 Almost there (catch-all)
else := {"effect": "request_more", "with": {"needs": ["invitation:from-member", "vrc:from-other-members:distinct>=2", "idvc:from-approved-idvp"], "presentation_definition": {"id": "vtc-phase4-member-vouched-idv"}}} if {
	true
}

# ---- helpers ----
has_valid_invitation if {
	input.evidence.invitation.verified
	not input.evidence.invitation.consumed
}

# Count of DISTINCT issuer DIDs across credentials of `t` whose issuer is trusted
# and holds `role` in this community.
credential_distinct_issuer_count(t, role) := count({c.issuer |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
})

# Same, but excluding the invitation issuer (the inviter can't both invite and self-vouch).
credential_distinct_issuer_count_excl_inviter(t, role) := count({c.issuer |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
	c.issuer != input.evidence.invitation.issuer
})
