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

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiZGlyZWN0b3J5Iiwicm91dGVzIjpbeyJuYW1lIjoiQWRtaW4gdmlld2VyIiwid2hlbiI6eyJhbGwiOlsidmlld2VyX2lzX2FkbWluIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6eyJmaWVsZHMiOlsiZGlkIiwicm9sZSIsImpvaW5lZF9hdCIsInN0YXR1cyJdfX19LHsibmFtZSI6IkF1dGhlbnRpY2F0ZWQgbWVtYmVyIiwid2hlbiI6eyJhbGwiOlsidmlld2VyX2lzX21lbWJlciJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsiZmllbGRzIjpbImRpZCIsInJvbGUiXX19fSx7Im5hbWUiOiJOb3QgYSBtZW1iZXIiLCJ3aGVuIjp7ImFsbCI6WyJhbHdheXMiXX0sInRoZW4iOnsiZWZmZWN0IjoiZGVueSIsIndpdGgiOnsiY29kZSI6Im5vdC1hLW1lbWJlciJ9fX1dfQ==

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
