package vtc.lkmv_merge

import future.keywords.if

# Compiled from lkmv-merge.ir.json by the VTC Rule IR compiler (illustrative).
# Per-action attestation: a Linux subsystem maintainer records that they
# merged a commit into their tree. The verdict's `allow` payload signals to
# the host that a MergeAttestation credential should be minted, bound to the
# actor's current role and the commit data carried in `evidence.request`.
# The IR's job is only to AUTHORIZE the attestation, not to format the
# resulting credential — that's a host-side responsibility (see
# vtc-ceremony-pipeline.md §3.5).

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Maintainer-authorized merge
decision := {"effect": "allow", "with": {"issues_attestation": "MergeAttestation", "obligations": ["chain-to-parents"]}} if {
	input.actor.role == "maintainer"
}

# P2 Not a maintainer
else := {"effect": "deny", "with": {"code": "lkmv-merge-requires-maintainer-role", "reason": "Only members holding role `maintainer` (or above) may issue MergeAttestations in this community."}} if {
	true
}
