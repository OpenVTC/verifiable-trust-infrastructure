# Default `directoryWrite` policy — what a member directory card may hold.
#
# Evaluated over a member's `vtc/directory/card/update` and an administrator's
# `vtc/directory/card/assert`, after the community's own checks: the field
# exists and is active, its writer may write it, the value fits its type and
# constraints, and no visibility exceeds the field's ceiling. Those are never
# this policy's to relax.
#
# This policy may refuse a value, and nothing else. It is never asked about a
# change that only narrows what anyone can see or find — a member may always
# hide more — and nothing it returns can widen a visibility.
#
# Input:
#   input.operation        "update" (the member) or "assert" (an administrator)
#   input.actor            { did, role, directoryAdmin }
#   input.subject          { entryId }
#   input.card             the card as it would be: values, visibility,
#                          discoverability, introductions
#   input.changed          the fields the document named
#   input.others           for "update": each other card's nickname, so a
#                          community can make nicknames unique
#
# Refuse with:
#   {"effect": "deny", "with": {"code": "...", "field": "<key>", "reason": "..."}}
# which the member is shown as `valueRefused` naming the field.
#
# The shipped posture accepts every value the community's checks accept. A
# community that wants unique nicknames uploads, for example:
#
#   decision := {"effect": "deny", "with": {"code": "nickname-taken",
#       "field": "nickname", "reason": "that nickname is taken"}} if {
#       input.operation == "update"
#       "nickname" in input.changed
#       lower(input.card.values.nickname) in {lower(n) | some n in input.others.nicknames}
#   }

package vtc.directory_write

import rego.v1

default decision := {"effect": "allow"}
