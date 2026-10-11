# Default `admission` policy — direct admission by an administrator.
#
# Admission is the constructive ceremony an administrator starts without a
# join request: **Add a member** (`vtc/members/admit/0.1`) admits a DID the
# community has never vetted, and **Make this a membership**
# (`vtc/members/make-membership/0.1`) gives an existing ACL entry — a bootstrap
# administrator, typically — the member record and credentials a completed
# join would have given it. Both bypass the join criteria, so a community
# decides here whether they may happen at once or need a second
# administrator's approval.
#
# The host has already checked everything that is not a matter of community
# policy before this runs, and checks it again when an approved admission
# executes: the actor holds `vtc.members.manage`, a role other than `member`
# is assigned by an actor holding `vtc.roles.assign` and only within its own
# authority (vtc-admin-roles.md §6.3), `admin` is never seated this way, and
# the subject is not already a member. A policy cannot widen any of that.
#
# Effects:
#
# - `allow`   → admitted now: the ACL entry (for an add), the member record
#   and the membership credentials (VMC + role VAC) are written at once. The
#   role is the one the administrator asked for; `with.role`, if given, must
#   name it.
# - `refer`   → parked in the action list. Another holder of
#   `vtc.members.manage` (never the requester, never the subject) approves it
#   there, and it then runs itself, every check re-run. The requester confirms
#   with a passkey gesture bound to the one admission when it is parked.
# - `deny`    → refused, with `with.code`.
#
# The input:
#
#   input.actor.did, input.actor.role        the administrator asking
#   input.subject.did                        who would be admitted
#   input.evidence.request.action            "add" | "make-membership"
#   input.evidence.request.role              the community role it would hold
#   input.evidence.request.administrative    whether that role carries
#                                            administrative authority
#   input.evidence.request.returning         whether the subject is a former
#                                            member (a removed record)
#
# This default admits every direct admission at once, as the console did
# before the policy existed. To require a second administrator's approval for
# all of them, replace the default below with
#
#   default decision := {"effect": "refer", "with": {"queue": "second-admin"}}
#
# or keep it and add a rule for the cases that need one, e.g. any role but
# `member`, or a returning member:
#
#   decision := {"effect": "refer", "with": {"queue": "second-admin"}} if {
#       input.evidence.request.role != "member"
#   }

package vtc.admission

import rego.v1

default decision := {"effect": "allow", "with": {}}
