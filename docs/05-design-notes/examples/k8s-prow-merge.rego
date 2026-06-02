package vtc.k8s_prow_merge

import future.keywords.if
import future.keywords.in

# Compiled from k8s-prow-merge.ir.json by the VTC Rule IR compiler (illustrative).
# Per-action attestation: Kubernetes Prow (a bot actor holding role `merge-bot`
# via a forward-looking AutomationMembershipCredential) records a PR merge
# after collecting ≥1 approve ReviewAttestation + ≥1 lgtm ReviewAttestation
# from the underlying code review. The verdict's `allow` payload signals to
# the host that a MergeAttestation should be minted, chaining to the underlying
# ReviewAttestations. Five routes implement graceful degradation: missing one,
# the other, both, or wrong-actor each give a distinct verdict.
# (See vtc-ceremony-pipeline.md §3.5 for the temporal verification model.)

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Prow merge with approver + reviewer signoff
decision := {"effect": "allow", "with": {"issues_attestation": "MergeAttestation", "obligations": ["chain-to-reviews", "chain-to-parents"]}} if {
	input.actor.role == "merge-bot"
	credential_count_from_role("ReviewAttestation", "approver") >= 1
	credential_distinct_issuer_count("ReviewAttestation", "reviewer") >= 1
}

# P2 Missing approver signoff (bot + reviewer-lgtm only)
else := {"effect": "request_more", "with": {"needs": ["review:approve-from-approver"]}} if {
	input.actor.role == "merge-bot"
	credential_distinct_issuer_count("ReviewAttestation", "reviewer") >= 1
}

# P3 Missing reviewer signoff (bot + approver-only)
else := {"effect": "request_more", "with": {"needs": ["review:lgtm-from-reviewer"]}} if {
	input.actor.role == "merge-bot"
	credential_count_from_role("ReviewAttestation", "approver") >= 1
}

# P4 Bot present, nothing else
else := {"effect": "request_more", "with": {"needs": ["review:approve-from-approver", "review:lgtm-from-reviewer"]}} if {
	input.actor.role == "merge-bot"
}

# P5 Not the merge bot
else := {"effect": "deny", "with": {"code": "k8s-prow-merge-requires-bot-actor", "reason": "Only an automation actor holding role `merge-bot` may issue MergeAttestations in this community."}} if {
	true
}

# ---- helpers ----
# Count of credentials matching (type, community role), all VERIFIED.
# Used by the approver clause where min=1 (no distinct-issuer constraint needed).
credential_count_from_role(t, role) := count([c |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
])

# Distinct issuers of credentials matching (type, community role), all VERIFIED.
# Used by the reviewer clause to require an LGTM from a distinct human.
credential_distinct_issuer_count(t, role) := count({c.issuer |
	some c in input.evidence.presentation.credentials
	c.type == t
	c.issuer_trusted
	c.issuer_role_in_community == role
	c.status == "valid"
})
