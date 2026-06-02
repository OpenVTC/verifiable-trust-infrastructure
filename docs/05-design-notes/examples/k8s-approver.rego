package vtc.k8s_approver

import future.keywords.if
import future.keywords.in

# Compiled from k8s-approver.ir.json by the VTC Rule IR compiler (illustrative).
# Kubernetes Reviewer → Approver promotion: a candidate currently holding the
# `reviewer` role is promoted to `approver` when at least two distinct existing
# Approvers sign PromotionEndorsementCredentials. Mirrors the OWNERS-file
# promotion pattern from contributors/devel/community-membership.md.
# The privilege ceiling (no admin from a capability-escalation ceremony) is
# host-enforced. `approver` is not `admin`, so it holds.

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Promoted by quorum of approvers (≥2 distinct endorsers)
decision := {"effect": "allow", "with": {"role": "approver", "obligations": ["accept-approver-duties"]}} if {
	input.state.subject_member.role == "reviewer"
	credential_distinct_issuer_count("PromotionEndorsementCredential", "approver") >= 2
}

# P2 Awaiting endorsements (reviewer, but <2 distinct approver endorsements)
else := {"effect": "request_more", "with": {"needs": ["endorsement:from-approver:distinct>=2"], "presentation_definition": {"id": "vtc-k8s-approver-endorsements"}}} if {
	input.state.subject_member.role == "reviewer"
}

# P3 Not yet a reviewer (structural prerequisite fails)
else := {"effect": "deny", "with": {"code": "k8s-approver-requires-reviewer-first", "reason": "Candidate must first hold role `reviewer` in this community before being promoted to `approver`."}} if {
	true
}

# ---- helpers ----
# Distinct issuers of credentials matching (type, community role), all VERIFIED.
credential_distinct_issuer_count(t, role) := count({c.issuer |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
})
