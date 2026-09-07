# Default `rooms` policy — who may create a data room on this community.
#
# This governs **creation only**. Once a room exists, every operation on it is
# authorized by credentials the room itself issued, and this service's roster
# has no say — that is invariant I5 of the data-rooms design, and it is what
# lets a room move to another host. What a community decides here is narrower
# and entirely its own: whether to lend its disk.
#
# The shipped posture is §7.4's: members may create `open` and `attributed`
# rooms; `private` is denied until an operator enables it. Not because a private
# room is dangerous, but because a community that has not decided should not
# discover it is hosting rooms whose membership it cannot see. To permit them,
# upload a policy with the `private` clause removed.
#
# The input carries the creator (with their community standing) and the room's
# identifier, visibility and owner. It deliberately does NOT carry the hosting
# axes the design sketches (`didControlledBy` / `contentStoredAt`): the
# published `rooms/create/0.1` schema has no member for either, so no host can
# know them, and inventing them locally would put this service's rooms out of
# conformance with the schema every other host reads.

package vtc.rooms

import rego.v1

# Structural totality. A policy that answers nothing is refused by the host
# rather than read as consent, but saying so here means the common refusal
# carries a code an operator can act on.
default decision := {"effect": "deny", "with": {
	"code": "not-a-member",
	"reason": "this community hosts rooms for its own members",
}}

# A private room asks this community to store content it cannot read, for
# members it cannot enumerate. Permitted only once an operator has said so.
decision := {"effect": "deny", "with": {
	"code": "private-tier-not-enabled",
	"reason": "this community has not enabled private rooms; upload a rooms policy that permits them",
}} if {
	input.actor.member == true
	input.room.visibility == "private"
}

# The ordinary case: a member creating a room whose tier this community serves.
else := {"effect": "allow"} if {
	input.actor.member == true
	input.room.visibility in {"open", "attributed"}
}
