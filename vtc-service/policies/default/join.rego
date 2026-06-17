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
# Default posture: a submission presenting a **valid, trusted, unconsumed
# invitation** (VIC) auto-admits as a member — the community explicitly
# invited this DID, so no human review is needed; a submission with a
# **trusted, valid** credential also auto-admits; everything else is
# referred to the moderator queue for human review (the request lands
# Pending — the same gate the pre-pipeline `policies.open` default
# produced). Operators replace this with their own decision policy (e.g.
# admit only on an invitation, require a code-of-conduct agreement).
#
# The privilege ceiling is host-enforced around this policy: a `join`
# verdict may never grant `admin`.

package vtc.join

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiam9pbiIsInJvdXRlcyI6W3sibmFtZSI6IlZhbGlkIGludml0YXRpb24iLCJ3aGVuIjp7ImFsbCI6WyJoYXNfdmFsaWRfaW52aXRhdGlvbiJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsicm9sZSI6Im1lbWJlciJ9fX0seyJuYW1lIjoiVHJ1c3RlZCBjcmVkZW50aWFsIiwid2hlbiI6eyJhbGwiOlsiaG9sZHNfYW55X3RydXN0ZWQiXX0sInRoZW4iOnsiZWZmZWN0IjoiYWxsb3ciLCJ3aXRoIjp7InJvbGUiOiJtZW1iZXIifX19LHsibmFtZSI6Ik1vZGVyYXRvciByZXZpZXciLCJ3aGVuIjp7ImFsbCI6WyJhbHdheXMiXX0sInRoZW4iOnsiZWZmZWN0IjoicmVmZXIiLCJ3aXRoIjp7InF1ZXVlIjoibW9kZXJhdG9yIn19fV19

# structural totality — unmatched submissions go to moderator review
default decision := {"effect": "refer", "with": {"queue": "moderator"}}

# A valid, trusted, unconsumed invitation (VIC) auto-admits at the role the
# invitation grants — the community (or a trusted third party) explicitly
# invited this DID. `verified` / `issuer_trusted` / `consumed` are host-resolved
# facts: `verified` = signature + holder-binding + validity + revocation all
# checked; `issuer_trusted` = the issuer is the community itself or a
# registry-recognised peer; `consumed` = the single-use VIC was already
# redeemed. The granted role comes from the VIC's `scopes` (`role:<name>`,
# default `member`); the host's privilege ceiling still forbids `admin` on join.
decision := {"effect": "allow", "with": {"role": invited_role}} if {
	has_valid_invitation
}

# A presented credential from a trusted issuer auto-admits as a member.
decision := {"effect": "allow", "with": {"role": "member"}} if {
	some c in input.evidence.presentation.credentials
	c.issuer_trusted
	c.status == "valid"
}

has_valid_invitation if {
	input.evidence.invitation.verified
	input.evidence.invitation.issuer_trusted
	not input.evidence.invitation.consumed
}

# The role an invitation grants: the first `role:<name>` scope it carries,
# else `member`.
default invited_role := "member"

invited_role := role if {
	some s in input.evidence.invitation.scopes
	startswith(s, "role:")
	role := substring(s, 5, -1)
}
