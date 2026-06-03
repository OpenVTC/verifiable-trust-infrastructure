# Default `join` policy — the join ceremony decision spine
# (ceremony-pipeline design §4; supersedes the `policies.open` boolean
# shape).
#
# Join is the constructive ceremony: a DID asks to join the community.
# The submit handler verifies the VP holder-binding, assembles verified
# Facts, runs `data.vtc.join.decision`, and realizes the verdict —
# `allow` auto-admits (issues the membership credential), `refer` queues
# the request as Pending for admin review, `deny` rejects it, and
# `request_more` defers pending more evidence.
#
# Default posture: a submission with a **trusted, valid** credential
# auto-admits; everything else is referred to the moderator queue for
# human review (the request lands Pending — the same gate the
# pre-pipeline `policies.open` default produced). Operators replace this
# with their own decision policy (e.g. admit on a specific credential
# type, gate on an invitation, require a code-of-conduct agreement).
#
# The privilege ceiling is host-enforced around this policy: a `join`
# verdict may never grant `admin`.

package vtc.join

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiam9pbiIsInJvdXRlcyI6W3sibmFtZSI6IlRydXN0ZWQgY3JlZGVudGlhbCIsIndoZW4iOnsiYWxsIjpbImhvbGRzX2FueV90cnVzdGVkIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6eyJyb2xlIjoibWVtYmVyIn19fSx7Im5hbWUiOiJNb2RlcmF0b3IgcmV2aWV3Iiwid2hlbiI6eyJhbGwiOlsiYWx3YXlzIl19LCJ0aGVuIjp7ImVmZmVjdCI6InJlZmVyIiwid2l0aCI6eyJxdWV1ZSI6Im1vZGVyYXRvciJ9fX1dfQ==

# structural totality — unmatched submissions go to moderator review
default decision := {"effect": "refer", "with": {"queue": "moderator"}}

# A presented credential from a trusted issuer auto-admits as a member.
decision := {"effect": "allow", "with": {"role": "member"}} if {
	some c in input.evidence.presentation.credentials
	c.issuer_trusted
	c.status == "valid"
}
