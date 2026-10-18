# Default `directory` policy — who may read the member directory, and what
# of each entry a policy narrows.
#
# The community computes every projection itself (VTI-DIR-020): a field
# leaves only where the member's own visibility and the field's ceiling both
# admit the viewer. This policy is asked about each entry after that, and can
# only narrow it — `deny` withholds the entry, and `allow` with
# `with.fields` keeps only the fields it names. It can never show a field the
# community withheld: naming one changes nothing (VTI-DIR-021).
#
# `allow` with no `fields` narrows nothing: the viewer sees what the members'
# own choices and the community's ceilings allow. That is the shipped
# posture. Before directory cards existed, this default answered members with
# `fields: ["did", "role"]`; that default is replaced at boot while it is
# still the workspace's own row, and an operator's own policy is left alone.
#
# Input, beside the ceremony facts (`input.actor`, `input.subject`,
# `input.state.subject_member`):
#   input.evidence.request.entryId           the entry
#   input.evidence.request.fields_requested  what the community already allows
#   input.evidence.request.listing           listed | findable | hidden
#   input.evidence.request.viewer            { directoryAdmin, membersManage, connected }

package vtc.directory

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiZGlyZWN0b3J5Iiwicm91dGVzIjpbeyJuYW1lIjoiTWVtYmVyIG9yIGFkbWluaXN0cmF0b3IiLCJ3aGVuIjp7ImFsbCI6WyJ2aWV3ZXJfaXNfbWVtYmVyIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6e319fSx7Im5hbWUiOiJOb3QgYSBtZW1iZXIiLCJ3aGVuIjp7ImFsbCI6WyJhbHdheXMiXX0sInRoZW4iOnsiZWZmZWN0IjoiZGVueSIsIndpdGgiOnsiY29kZSI6Im5vdC1hLW1lbWJlciJ9fX1dfQ==

# structural totality — an unidentified reader sees nothing
default decision := {"effect": "deny", "with": {"code": "not-a-member"}}

# Member or administrator — the community's own projection, unnarrowed
decision := {"effect": "allow", "with": {}} if {
	input.actor.authenticated == true
}
