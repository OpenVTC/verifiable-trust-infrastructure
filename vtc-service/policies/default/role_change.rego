# Default `role-change` policy — the role-change ceremony decision
# spine (ceremony-pipeline design §4).
#
# Role-change is the mutating ceremony: a member's role changes in
# place (the DID + VMC are unchanged; the role VEC is re-minted). It
# is the one ceremony whose `allow` may grant `admin` — but only with
# a verified step-up. The host enforces the rest around this policy:
# the step-up-for-admin invariant (an admin grant without
# `evidence.request.step_up` is vetoed) and no-last-admin (a demotion
# that would drop the community to zero admins is refused, 409).
#
# Decision logic:
# - a **standard** change (target is member / moderator / custom) is
#   allowed, granting the requested role;
# - **promotion to admin with a verified step-up** is allowed;
# - **promotion to admin without step-up** is referred to the step-up
#   queue (the operator must complete the reauth ceremony);
# - everything else denies.

package vtc.role_change

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoicm9sZUNoYW5nZSIsInJvdXRlcyI6W3sibmFtZSI6IlN0YW5kYXJkIHJvbGUiLCJ3aGVuIjp7ImFsbCI6WyJ0YXJnZXRfcm9sZV9zdGFuZGFyZCJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsicm9sZSI6IiR0YXJnZXQifX19LHsibmFtZSI6IkFkbWluIHdpdGggc3RlcC11cCIsIndoZW4iOnsiYWxsIjpbInByb21vdGVzX3RvX2FkbWluIiwic3RlcF91cF9kb25lIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6eyJyb2xlIjoiYWRtaW4ifX19LHsibmFtZSI6IkFkbWluIG5lZWRzIHN0ZXAtdXAiLCJ3aGVuIjp7ImFsbCI6WyJwcm9tb3Rlc190b19hZG1pbiJdfSwidGhlbiI6eyJlZmZlY3QiOiJyZWZlciIsIndpdGgiOnsicXVldWUiOiJzdGVwLXVwIn19fSx7Im5hbWUiOiJSZWZ1c2VkIiwid2hlbiI6eyJhbGwiOlsiYWx3YXlzIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImRlbnkiLCJ3aXRoIjp7ImNvZGUiOiJuby1tYXRjaGluZy1yb3V0ZSJ9fX1dfQ==

# structural totality — unmatched role changes are refused
default decision := {"effect": "deny", "with": {"code": "no-matching-route"}}

# Standard role change — member / moderator / custom.
decision := {"effect": "allow", "with": {"role": target_role}} if {
	target_role != "admin"
}

# Promotion to admin with a verified step-up.
else := {"effect": "allow", "with": {"role": "admin"}} if {
	target_role == "admin"
	input.evidence.request.step_up == true
}

# Promotion to admin without step-up — needs the reauth ceremony.
else := {"effect": "refer", "with": {"queue": "step-up"}} if {
	target_role == "admin"
}

# ---- helpers ----
target_role := input.evidence.request.target_role
