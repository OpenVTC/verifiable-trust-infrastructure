# Default `groups` policy — the community's groups (`vtc/groups/*`).
#
# Evaluated after the community's own checks, over a group's creation and a
# member joining one or asking to: the caller holds `vtc.groups.manage` for a
# creation, the member is active, the group's settings are well formed and a
# static group's join policy admits the join.
# Those are never this policy's to relax.
#
# This policy may refuse, and nothing else. It never makes someone a member,
# a manager or a holder of any authority.
#
# Input:
#   input.operation   "create" | "join" | "request"
#   input.now         evaluation time
#   input.actor       { did, role, member, manager }
#                       manager: the caller manages the group (or every group)
#   input.group       { groupId, kind, joinPolicy, visibility, showMembers,
#                       issuesCredentials, memberCount }
#                       (groupId is empty and memberCount 0 on "create")
#
# Refuse with:
#   {"effect": "deny", "with": {"code": "...", "reason": "..."}}
# which the caller is shown as the task's `policyRefused`.
#
# The shipped posture allows whatever the community's checks allow. A
# community that caps group size, for example, uploads:
#
#   decision := {"effect": "deny", "with": {"code": "group-full",
#       "reason": "this group is full"}} if {
#       input.operation in {"join", "request"}
#       input.group.memberCount >= 200
#   }

package vtc.groups

import rego.v1

default decision := {"effect": "allow"}
