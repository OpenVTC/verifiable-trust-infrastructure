package vtc.directory

import future.keywords.if

# Compiled from directory.ir.json by the VTC Rule IR compiler (illustrative).
# A SYNCHRONOUS read ceremony: `allow` carries a FIELD PROJECTION, not a boolean.
# No thread, no state write — the host returns exactly `with.fields` of the subject.

# structural totality — a non-member sees nothing
default decision := {"effect": "deny", "with": {"code": "not-a-member"}}

# P1 Admin viewer — full record
decision := {"effect": "allow", "with": {"fields": ["did", "role", "joined_at", "status", "extensions"]}} if {
	input.actor.role == "admin"
}

# P2 Member viewer — minimal projection
else := {"effect": "allow", "with": {"fields": ["did", "role"]}} if {
	input.actor.authenticated == true
}
