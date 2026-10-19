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
#   input.evidence.request.viewer            { directoryAdmin, membersManage, connected, public }
#
# `viewer.public` is true, and `input.actor.authenticated` false, for one
# question only: what a member's external card may carry
# (`vtc/directory/card/publish`). The community has already kept just the
# values the member made `public` under a `public` ceiling; denying here, or
# naming fewer fields, keeps those values off every external card. No
# directory read is ever answered to the public.

package vtc.directory

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiZGlyZWN0b3J5Iiwicm91dGVzIjpbeyJuYW1lIjoiTWVtYmVyIG9yIGFkbWluaXN0cmF0b3IiLCJ3aGVuIjp7ImFsbCI6WyJ2aWV3ZXJfaXNfbWVtYmVyIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6e319fSx7Im5hbWUiOiJUaGUgcHVibGljLCBmb3IgYW4gZXh0ZXJuYWwgY2FyZCIsIndoZW4iOnsiYWxsIjpbInZpZXdlcl9pc19wdWJsaWMiXX0sInRoZW4iOnsiZWZmZWN0IjoiYWxsb3ciLCJ3aXRoIjp7fX19LHsibmFtZSI6Ik5vdCBhIG1lbWJlciIsIndoZW4iOnsiYWxsIjpbImFsd2F5cyJdfSwidGhlbiI6eyJlZmZlY3QiOiJkZW55Iiwid2l0aCI6eyJjb2RlIjoibm90LWEtbWVtYmVyIn19fV19

# structural totality — anyone else sees nothing
default decision := {"effect": "deny", "with": {"code": "not-a-member"}}

# Member or administrator — the community's own projection, unnarrowed
decision := {"effect": "allow", "with": {}} if {
	input.actor.authenticated == true
}

# The public, for an external card — what members chose to make public, unnarrowed
decision := {"effect": "allow", "with": {}} if {
	input.evidence.request.viewer.public == true
}
