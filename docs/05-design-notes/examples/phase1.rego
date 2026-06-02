package vtc.phase1

import future.keywords.if

# Compiled from phase1.ir.json by the VTC Rule IR compiler (illustrative).
# Phase 1 is community GENESIS: the initiator self-bootstraps a brand-new VTC.
# Per the VTC Bootstrapping spec, Phase 1 policy is HARDCODED in the Personal
# Network Manager — the VTA doesn't exist yet to evaluate this. The IR here is
# a degenerate representation kept for design completeness and the visual guide;
# it surfaces the layered-trust progression that begins at "initiator".

# structural totality — compiler-appended, operator cannot remove
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# P1 Initiator self-bootstrap
decision := {"effect": "allow", "with": {"role": "initiator", "obligations": []}} if {
	input.actor.role == "initiator"
}

# P2 Default deny (explicit catch-all — anyone other than the initiator)
else := {"effect": "deny", "with": {"code": "phase1-initiator-only", "reason": "Phase 1 admits only the initiator (PNM-side bootstrap)."}} if {
	true
}
