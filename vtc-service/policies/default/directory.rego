# Default `directory` policy — the ceremony decision spine
# (ceremony-pipeline design §4; supersedes the Phase-5 boolean
# placeholder).
#
# The directory ceremony is the read-only instance of the decision
# pipeline: `allow` carries a FIELD PROJECTION (`with.fields`), not a
# boolean. The host runs `data.vtc.directory.decision` over the
# verified Facts (`input.actor` / `input.subject` / `input.state`),
# realizes the verdict by returning exactly `with.fields` of the
# subject, and intersects those fields with the community PII-boundary
# whitelist before they cross the wire.
#
# Privacy floor: a non-member viewer sees nothing; an authenticated
# member sees `did` + `role`; an admin sees the fuller record. An
# operator can upload a wider- or narrower-scope policy; the PII
# boundary still caps what any policy can project.

package vtc.directory

import rego.v1

# structural totality — a non-member sees nothing
default decision := {"effect": "deny", "with": {"code": "not-a-member"}}

# Admin viewer — fuller record
decision := {"effect": "allow", "with": {"fields": ["did", "role", "joined_at", "status"]}} if {
	input.actor.role == "admin"
}

# Authenticated member viewer — minimal projection
else := {"effect": "allow", "with": {"fields": ["did", "role"]}} if {
	input.actor.authenticated == true
}
