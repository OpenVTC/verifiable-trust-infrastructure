# Default `removal` policy — the leave/removal ceremony decision spine
# (ceremony-pipeline design §4; supersedes the boolean Phase-2 shape).
#
# The leave ceremony is the destructive instance of the decision
# pipeline: the host assembles verified Facts, runs
# `data.vtc.removal.decision`, and realizes the verdict via the
# effect executor (delete ACL + apply disposition + revoke). The
# package stays `vtc.removal` (PolicyPurpose::Removal); the pipeline
# calls the ceremony "leave".
#
# What the host enforces around this policy (never in Rego):
# - the no-last-admin invariant (refuses to leave zero admins, 409),
# - the AdminAuth gate on the admin-remove endpoint,
# - the final disposition (caller request > member preference > the
#   `with.disposition` below > tombstone).
#
# Decision logic:
# - **self-leave** (`actor.did == subject.did`) is unconditional — a
#   member may always leave.
# - an **admin removing another member** is allowed unless the subject
#   is themselves an admin (admins leave only via the promotion +
#   step-up path, never a casual admin-remove).
# - everything else denies.

package vtc.removal

import rego.v1

# This default is the visual form of the policy below — the admin-UI
# reads the header to render it in plain English, show a decision
# trace, and open it in the route-card editor. Keep it in step with the
# body if you hand-edit the Rego.
# @vtc-rule-ir: eyJwdXJwb3NlIjoicmVtb3ZhbCIsInJvdXRlcyI6W3sibmFtZSI6IlNlbGYtbGVhdmUiLCJ3aGVuIjp7ImFsbCI6WyJhY3Rvcl9pc19zZWxmIl19LCJ0aGVuIjp7ImVmZmVjdCI6ImFsbG93Iiwid2l0aCI6eyJkaXNwb3NpdGlvbiI6InRvbWJzdG9uZSJ9fX0seyJuYW1lIjoiQWRtaW4gcmVtb3ZlcyBub24tYWRtaW4iLCJ3aGVuIjp7ImFsbCI6WyJzdWJqZWN0X25vdF9hZG1pbiJdfSwidGhlbiI6eyJlZmZlY3QiOiJhbGxvdyIsIndpdGgiOnsiZGlzcG9zaXRpb24iOiJ0b21ic3RvbmUifX19LHsibmFtZSI6IlJlZnVzZWQiLCJ3aGVuIjp7ImFsbCI6WyJhbHdheXMiXX0sInRoZW4iOnsiZWZmZWN0IjoiZGVueSIsIndpdGgiOnsiY29kZSI6InJlbW92YWwtZGVuaWVkIn19fV19

# structural totality — unmatched removals are refused
default decision := {"effect": "deny", "with": {"code": "removal-denied"}}

# Self-leave — a member may always remove themselves.
decision := {"effect": "allow", "with": {"disposition": "tombstone"}} if {
	input.actor.did == input.subject.did
}

# Admin removing another member — allowed unless the subject is an admin.
else := {"effect": "allow", "with": {"disposition": "tombstone"}} if {
	input.state.subject_member.role != "admin"
}
