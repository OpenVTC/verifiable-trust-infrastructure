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
# Default posture: when the community's join criterion requires **peer
# identity vetting**, admission waits on it — the vetting rules below decide,
# and neither an invitation nor a trusted credential bypasses them. Otherwise
# a submission presenting a **valid, trusted, unconsumed invitation** (VIC)
# auto-admits as a member — the community explicitly invited this DID, so no
# human review is needed; a submission with a **trusted, valid** credential
# also auto-admits; everything else is referred to the moderator queue for
# human review (the request lands Pending — the same gate the pre-pipeline
# `policies.open` default produced). Operators replace this with their own
# decision policy (e.g. admit only on an invitation, require a code-of-conduct
# agreement).
#
# The privilege ceiling is host-enforced around this policy: a `join`
# verdict may never grant `admin`.

package vtc.join

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiam9pbiIsInJvdXRlcyI6W3sibmFtZSI6IlZldHRlcnMgdmVyaWZpZWQgZGlmZmVyZW50IGlkZW50aXRpZXMiLCJ3aGVuIjp7ImFsbCI6WyJ2ZXR0aW5nX2luY29uc2lzdGVudCJdfSwidGhlbiI6eyJlZmZlY3QiOiJyZWZlciIsIndpdGgiOnsicXVldWUiOiJ2ZXR0aW5nLXJldmlldyJ9fX0seyJuYW1lIjoiVmV0dGluZyBpbmNvbXBsZXRlIiwid2hlbiI6eyJhbGwiOlsidmV0dGluZ19pbmNvbXBsZXRlIl19LCJ0aGVuIjp7ImVmZmVjdCI6InJlcXVlc3RfbW9yZSIsIndpdGgiOnsibmVlZHMiOlsidmV0dGluZyJdfX19LHsibmFtZSI6IlZldHRlcnMgbm90IGluZGVwZW5kZW50Iiwid2hlbiI6eyJhbGwiOlsidmV0dGluZ19ub3RfaW5kZXBlbmRlbnQiXX0sInRoZW4iOnsiZWZmZWN0IjoicmVmZXIiLCJ3aXRoIjp7InF1ZXVlIjoidmV0dGluZy1yZXZpZXcifX19LHsibmFtZSI6IlZldHRpbmcgbmVlZHMgYW4gaW52aXRhdGlvbiIsIndoZW4iOnsiYWxsIjpbInZldHRpbmdfaW52aXRhdGlvbl9taXNzaW5nIl19LCJ0aGVuIjp7ImVmZmVjdCI6InJlcXVlc3RfbW9yZSIsIndpdGgiOnsibmVlZHMiOlsidmV0dGluZzppbnZpdGF0aW9uIl19fX0seyJuYW1lIjoiVmFsaWQgaW52aXRhdGlvbiIsIndoZW4iOnsiYWxsIjpbImhhc192YWxpZF9pbnZpdGF0aW9uIiwidmV0dGluZ19vayJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsicm9sZSI6Im1lbWJlciJ9fX0seyJuYW1lIjoiVmV0dGVkIiwid2hlbiI6eyJhbGwiOlsidmV0dGluZ19zYXRpc2ZpZWQiXX0sInRoZW4iOnsiZWZmZWN0IjoiYWxsb3ciLCJ3aXRoIjp7InJvbGUiOiJtZW1iZXIifX19LHsibmFtZSI6IlRydXN0ZWQgY3JlZGVudGlhbCIsIndoZW4iOnsiYWxsIjpbImhvbGRzX2FueV90cnVzdGVkIiwidmV0dGluZ19vayJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsicm9sZSI6Im1lbWJlciJ9fX0seyJuYW1lIjoiTW9kZXJhdG9yIHJldmlldyIsIndoZW4iOnsiYWxsIjpbImFsd2F5cyJdfSwidGhlbiI6eyJlZmZlY3QiOiJyZWZlciIsIndpdGgiOnsicXVldWUiOiJtb2RlcmF0b3IifX19XX0=

# structural totality — unmatched submissions go to moderator review
default decision := {"effect": "refer", "with": {"queue": "moderator"}}

# ---- Peer identity vetting (OpenVTC docs/design/vetting-process.md §10) ----
#
# `input.evidence.vetting` is present only when the criterion requires vetting.
# The host has already verified every statement, checked each issuer is an
# eligible vetter, and counted them against the community's own requirements;
# these rules decide on that count. The four outcomes are mutually exclusive by
# construction, and `satisfied` is the host's conjunction of "no needs",
# "commitments consistent" and "independence ok".

# The vetters did not all verify the same claimed identity.
decision := {"effect": "refer", "with": {"queue": "vetting-review"}} if {
	vetting_inconsistent
}

# Not enough yet. The host expands the generic `vetting` need into the precise
# shortfall (`vetting:statements:<n>`, `vetting:method:<m>:<n>`).
decision := {"effect": "request_more", "with": {"needs": ["vetting"]}} if {
	vetting_incomplete
}

# Enough statements, but more of them share a declared relationship with the
# applicant than the community allows.
decision := {"effect": "refer", "with": {"queue": "vetting-review"}} if {
	vetting_not_independent
}

# Vetting is met but the requirements also ask for an invitation.
decision := {"effect": "request_more", "with": {"needs": ["vetting:invitation"]}} if {
	vetting_invitation_missing
}

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
	vetting_ok
}

# Vetting met, no invitation: admit as a member.
decision := {"effect": "allow", "with": {"role": "member"}} if {
	vetting_satisfied
	not has_valid_invitation
}

# A presented credential from a trusted issuer auto-admits as a member.
decision := {"effect": "allow", "with": {"role": "member"}} if {
	some c in input.evidence.presentation.credentials
	c.issuer_trusted
	c.status == "valid"
	vetting_ok
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

vetting_inconsistent if {
	input.evidence.vetting.commitments_consistent == false
}

vetting_incomplete if {
	input.evidence.vetting.commitments_consistent == true
	count(input.evidence.vetting.needs) > 0
}

vetting_not_independent if {
	input.evidence.vetting.commitments_consistent == true
	count(input.evidence.vetting.needs) == 0
	input.evidence.vetting.independence_ok == false
}

vetting_invitation_missing if {
	input.evidence.vetting.satisfied == true
	input.evidence.vetting.invitation_required == true
	not has_valid_invitation
}

vetting_satisfied if {
	input.evidence.vetting.satisfied == true
	not vetting_invitation_missing
}

# No vetting is required, or the vetting required is met.
vetting_ok if not input.evidence.vetting

vetting_ok if vetting_satisfied
