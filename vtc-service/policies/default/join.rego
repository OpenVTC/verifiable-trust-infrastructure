# Default `join` policy — the join ceremony decision spine
# (ceremony-pipeline design §4).
#
# Join is the constructive ceremony: a DID asks to join the community.
# The submit handler verifies the submission, decides which of the
# community's published join criteria governs it and whether it meets it
# (`vtc/join-requests/submit/0.3`), assembles verified Facts, runs
# `data.vtc.join.decision`, and realizes the verdict — `allow` auto-admits
# (issues the membership credential), `refer` queues the request as Pending
# for admin review, `deny` rejects it, and `request_more` defers pending
# more evidence.
#
# The join criteria are the community's rules, and this default adds none:
# it does what the governing criterion says. `input.evidence.criterion` is
# the host's verdict on it — `met` when the submission meets every
# requirement the criterion states (credentials, vetting, an invitation, or
# none), and the criterion's `admission`:
#
# - met, `automatic` → admitted as a member (at the role an invitation's
#   `role:<name>` scope grants, when one was presented);
# - met, `review`    → referred to an administrator;
# - not met          → asked for what is missing (the host expands the
#   generic `criterion` need into the precise shortfall).
#
# Which criteria a community publishes — open, invitation-only, credential-
# gated, vetted, reviewed, or any combination — is its administrators'
# choice, made through `vtc/schemas/accepts/register`, not here. An operator
# replaces this policy only to *tighten* a decision (exclude an applicant,
# refer what a criterion would admit): the host holds every verdict to the
# criterion, so no policy admits a submission that does not meet it, and
# none admits on a `review` criterion. The privilege ceiling is
# host-enforced too: a `join` verdict may never grant `admin`.

package vtc.join

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoiam9pbiIsInJvdXRlcyI6W3sibmFtZSI6IkNyaXRlcmlvbiBtZXQg4oCUIGFkbWl0Iiwid2hlbiI6eyJhbGwiOlsiY3JpdGVyaW9uX21ldF9hdXRvbWF0aWMiXX0sInRoZW4iOnsiZWZmZWN0IjoiYWxsb3ciLCJ3aXRoIjp7InJvbGUiOiJtZW1iZXIifX19LHsibmFtZSI6IkNyaXRlcmlvbiBtZXQg4oCUIHJldmlldyIsIndoZW4iOnsiYWxsIjpbImNyaXRlcmlvbl9tZXRfcmV2aWV3Il19LCJ0aGVuIjp7ImVmZmVjdCI6InJlZmVyIiwid2l0aCI6eyJxdWV1ZSI6ImFkbWluLXJldmlldyJ9fX0seyJuYW1lIjoiQ3JpdGVyaW9uIG5vdCBtZXQiLCJ3aGVuIjp7ImFsbCI6WyJjcml0ZXJpb25fdW5tZXQiXX0sInRoZW4iOnsiZWZmZWN0IjoicmVxdWVzdF9tb3JlIiwid2l0aCI6eyJuZWVkcyI6WyJjcml0ZXJpb24iXX19fSx7Im5hbWUiOiJNb2RlcmF0b3IgcmV2aWV3Iiwid2hlbiI6eyJhbGwiOlsiYWx3YXlzIl19LCJ0aGVuIjp7ImVmZmVjdCI6InJlZmVyIiwid2l0aCI6eyJxdWV1ZSI6Im1vZGVyYXRvciJ9fX1dfQ==

# structural totality — a join decided under no criterion goes to review
# (the host refuses it regardless)
default decision := {"effect": "refer", "with": {"queue": "moderator"}}

# The criterion is met and admits automatically.
decision := {"effect": "allow", "with": {"role": invited_role}} if {
	criterion_met_automatic
}

# The criterion is met and admits after an administrator's review.
decision := {"effect": "refer", "with": {"queue": "admin-review"}} if {
	criterion_met_review
}

# The criterion is not met: ask for what it still needs.
decision := {"effect": "request_more", "with": {"needs": ["criterion"]}} if {
	criterion_unmet
}

criterion_met_automatic if {
	input.evidence.criterion.met == true
	input.evidence.criterion.admission == "automatic"
}

criterion_met_review if {
	input.evidence.criterion.met == true
	input.evidence.criterion.admission == "review"
}

criterion_unmet if {
	input.evidence.criterion.met == false
}

# The role an admission grants: the first `role:<name>` scope a valid,
# unconsumed invitation carries, else `member`. The host's privilege
# ceiling still forbids `admin` on join.
default invited_role := "member"

invited_role := role if {
	input.evidence.invitation.verified
	not input.evidence.invitation.consumed
	some s in input.evidence.invitation.scopes
	startswith(s, "role:")
	role := substring(s, 5, -1)
}
