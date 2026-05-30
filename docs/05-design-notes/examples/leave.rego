package vtc.leave

import future.keywords.if

# Compiled from leave.ir.json by the VTC Rule IR compiler (illustrative).
# IMPORTANT: the no-last-admin invariant is enforced by the HOST around this policy
# (vtc-mvp.md §10.2), NOT in Rego — a policy edit can never disable it.

# structural totality — compiler-appended
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Self-exit — member leaves voluntarily, choosing a disposition
decision := {"effect": "allow", "with": {"disposition": disposition}} if {
	input.actor.did == input.subject.did
}

# P2 Admin removing another admin → needs a second admin
else := {"effect": "refer", "with": {"queue": "second-admin"}} if {
	input.actor.role == "admin"
	input.state.subject_member.role == "admin"
}

# P3 Admin removing a non-admin member
else := {"effect": "allow", "with": {"disposition": "Tombstone"}} if {
	input.actor.role == "admin"
}

# ---- helpers ----
# "$request" in the IR → the disposition the actor asked for, else PolicyDefault
disposition := input.evidence.request.disposition if {
	input.evidence.request.disposition
} else := "PolicyDefault"
