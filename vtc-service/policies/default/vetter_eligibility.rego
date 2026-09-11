# Default `vetter_eligibility` policy — which members the automatic vetter-grant
# sweep names vetters.
#
# Evaluated only while an admin has automatic grants turned on
# (`PUT /v1/vetting/auto-grant`), once per active member per sweep:
#
# - `allow` grants the member a vetter role credential when they hold no live
#   grant;
# - `deny` revokes the grants the sweep itself issued — never one an admin made;
# - anything else (no decision, an unknown effect) is logged and changes nothing.
#
# Input:
#
#   did          the member's DID
#   status       "active"
#   roles        the member's community roles, e.g. ["member"]
#   tenureDays   whole days since the member joined
#   admittedVia  "genesis" | "vetting" | "invitation" | "open"
#   underReview  a vetting statement that counted toward their admission has
#                since been withdrawn
#   depth        vetting hops from a genesis member (0 for one), or null when
#                unknown
#
# The shipped posture names only the community's genesis members — members the
# community did not admit through a join request — and only while nothing about
# their own standing is in question. Whom else to trust as a vetter, and after
# how long, is the community's decision, not a default. Upload a policy that
# says so, for example:
#
#   decision := {"effect": "allow"} if {
#       input.status == "active"
#       input.underReview == false
#       input.admittedVia == "vetting"
#       input.tenureDays >= 180
#       is_number(input.depth)
#       input.depth <= 2
#   }

package vtc.vetter_eligibility

import rego.v1

default decision := {"effect": "deny"}

decision := {"effect": "allow"} if {
	input.status == "active"
	input.underReview == false
	input.admittedVia == "genesis"
}
